<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

session_name(SESSION_NAME);
session_start();

// ---------- helpers ----------
function db(): mysqli {
  static $db = null;
  if ($db) return $db;
  $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
  if ($db->connect_error) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>false,'error'=>'DB connection failed']);
    exit;
  }
  $db->set_charset('utf8mb4');
  return $db;
}

function json_out(array $data, int $code=200): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data);
  exit;
}

$raw = file_get_contents('php://input') ?: '';
$isJson = str_contains($_SERVER['CONTENT_TYPE'] ?? '', 'application/json');
$J = ($isJson && $raw) ? (json_decode($raw, true) ?: []) : [];

function param(string $k, $default=null) {
  global $J;
  return $J[$k] ?? $_POST[$k] ?? $_GET[$k] ?? $default;
}

function require_login(): array {
  if (!isset($_SESSION['uid'], $_SESSION['role'], $_SESSION['username'])) {
    json_out(['ok'=>false,'error'=>'Not authenticated'], 401);
  }
  return [
    'id' => (int)$_SESSION['uid'],
    'role' => (string)$_SESSION['role'],
    'username' => (string)$_SESSION['username'],
  ];
}

function is_ia(array $u): bool { return strtoupper($u['role']) === 'IA'; }

function can_view_scope(array $u, string $scope): bool {
  $scope = strtoupper($scope);
  if (is_ia($u)) return true;
  if ($scope === 'ALL') return true;
  return $scope === strtoupper($u['role']);
}

function can_edit_item(array $u, array $item): bool {
  if (is_ia($u)) return true;
  if ((int)$item['owner_id'] === (int)$u['id']) return true;
  // collab edit inside own scope, BUT ALL is read-only unless owner/IA
  $scope = strtoupper((string)$item['scope']);
  if ($scope === 'ALL') return false;
  return $scope === strtoupper($u['role']);
}

function can_delete_item(array $u, array $item): bool {
  return is_ia($u) || ((int)$item['owner_id'] === (int)$u['id']);
}

function log_action(int $uid, string $action, ?string $meta=null): void {
  $db = db();
  $stmt = $db->prepare("INSERT INTO logs (user_id, action, meta) VALUES (?,?,?)");
  $stmt->bind_param("iss", $uid, $action, $meta);
  $stmt->execute();
  $stmt->close();
}

function clean_name(string $s): string {
  $s = trim($s);
  $s = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', $s) ?? $s;
  $s = preg_replace('/[\\\\\\/]/', '-', $s) ?? $s;
  return trim($s);
}

function get_item_or_404(int $id): array {
  $db = db();
  $stmt = $db->prepare("SELECT * FROM items WHERE id=? LIMIT 1");
  $stmt->bind_param("i", $id);
  $stmt->execute();
  $res = $stmt->get_result();
  $item = $res->fetch_assoc();
  $stmt->close();
  if (!$item) json_out(['ok'=>false,'error'=>'Item not found'], 404);
  return $item;
}

function get_parent_scope(?int $parentId): ?string {
  if ($parentId === null) return null;
  $p = get_item_or_404($parentId);
  if (strtoupper($p['type']) !== 'FOLDER') json_out(['ok'=>false,'error'=>'Parent is not a folder'], 400);
  return strtoupper((string)$p['scope']);
}

// ---------- router ----------
$action = (string)param('action', '');
if (!$action) json_out(['ok'=>false,'error'=>'Missing action'], 400);

// ---- Investigations helpers (PI/IA only, persisted in uploads/) ----
const INV_STORE = __DIR__ . '/uploads/investigations.json';

function ensure_uploads_dir(): void {
  $dir = __DIR__ . '/uploads';
  if (!is_dir($dir)) mkdir($dir, 0775, true);
}

function load_investigations(): array {
  ensure_uploads_dir();
  if (!is_file(INV_STORE)) return [];
  $raw = file_get_contents(INV_STORE);
  if ($raw === false || $raw === '') return [];
  $decoded = json_decode($raw, true);
  return is_array($decoded) ? $decoded : [];
}

function save_investigations(array $list): void {
  ensure_uploads_dir();
  file_put_contents(INV_STORE, json_encode($list, JSON_PRETTY_PRINT));
}

function require_investigator(array $u): void {
  $role = strtoupper((string)$u['role']);
  if (!in_array($role, ['PI', 'IA'], true)) {
    json_out(['ok'=>false,'error'=>'Investigations restricted'], 403);
  }
}

function investigator_label(array $u): string {
  $role = strtoupper((string)$u['role']);
  if ($role === 'PI' || $role === 'IA') return 'Investigator ' . $u['username'];
  return 'Agent ' . $u['username'];
}

// DOWNLOAD is special (binary)
if ($action === 'download') {
  $u = require_login();
  $id = (int)param('id', 0);
  if ($id <= 0) { http_response_code(400); exit; }
  $item = get_item_or_404($id);
  if (strtoupper($item['type']) !== 'UPLOAD') { http_response_code(400); exit; }
  if (!can_view_scope($u, (string)$item['scope'])) { http_response_code(403); exit; }

  $path = (string)$item['storage_path'];
  if (!$path || !is_file($path)) { http_response_code(404); exit; }

  log_action($u['id'], 'download', "id={$id};name={$item['name']}");

  $filename = basename((string)$item['name']);
  $mime = $item['mime'] ?: 'application/octet-stream';
  header('Content-Type: ' . $mime);
  header('Content-Length: ' . filesize($path));
  header('Content-Disposition: attachment; filename="' . str_replace('"','',$filename) . '"');
  readfile($path);
  exit;
}

switch ($action) {
  // ---- auth ----
  case 'login': {
    $username = strtoupper(trim((string)param('username','')));
    $password = (string)param('password','');
    if (!$username || !$password) json_out(['ok'=>false,'error'=>'Missing credentials'], 400);

    $db = db();
    $stmt = $db->prepare("SELECT id, username, pass_hash, role, status FROM users WHERE username=? LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();

    if (!$row || $row['status'] !== 'ACTIVE' || !password_verify($password, (string)$row['pass_hash'])) {
      json_out(['ok'=>false,'error'=>'Invalid credentials'], 403);
    }

    $_SESSION['uid'] = (int)$row['id'];
    $_SESSION['username'] = (string)$row['username'];
    $_SESSION['role'] = (string)$row['role'];

    log_action((int)$row['id'], 'login', 'ok');

    json_out(['ok'=>true,'user'=>[
      'id'=>(int)$row['id'],
      'username'=>(string)$row['username'],
      'role'=>(string)$row['role'],
    ]]);
  }

  case 'logout': {
    $u = require_login();
    log_action($u['id'], 'logout', (string)param('mode','logout'));
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
      $params = session_get_cookie_params();
      setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        (bool)$params["secure"], (bool)$params["httponly"]
      );
    }
    session_destroy();
    json_out(['ok'=>true]);
  }

  case 'me': {
    if (!isset($_SESSION['uid'])) json_out(['ok'=>false,'user'=>null]);
    json_out(['ok'=>true,'user'=>[
      'id'=>(int)$_SESSION['uid'],
      'username'=>(string)$_SESSION['username'],
      'role'=>(string)$_SESSION['role'],
    ]]);
  }

  // ---- investigations (PI / IA only) ----
  case 'inv_list': {
    $u = require_login();
    require_investigator($u);
    $all = load_investigations();
    json_out(['ok'=>true,'investigations'=>$all]);
  }

  case 'inv_create': {
    $u = require_login();
    require_investigator($u);
    $title = clean_name((string)param('title',''));
    $tagsRaw = (string)param('tags','');
    if (!$title) json_out(['ok'=>false,'error'=>'Title required'], 400);
    $tags = array_values(array_filter(array_map('trim', explode(',', $tagsRaw)), fn($t)=>$t !== ''));
    $tags = array_slice($tags, 0, 12);

    $all = load_investigations();
    $inv = [
      'id' => uniqid('inv_', true),
      'title' => $title,
      'tags' => $tags,
      'created_at' => date(DATE_ATOM),
      'created_by' => investigator_label($u),
      'entries' => [],
    ];
    array_unshift($all, $inv);
    save_investigations($all);
    log_action($u['id'], 'inv_create', $title);
    json_out(['ok'=>true,'investigation'=>$inv]);
  }

  case 'inv_update_tags': {
    $u = require_login();
    require_investigator($u);
    $id = (string)param('id','');
    $tagsRaw = (string)param('tags','');
    $tags = array_values(array_filter(array_map('trim', explode(',', $tagsRaw)), fn($t)=>$t !== ''));
    $tags = array_slice($tags, 0, 12);

    $all = load_investigations();
    foreach ($all as &$inv) {
      if ($inv['id'] === $id) {
        $inv['tags'] = $tags;
        save_investigations($all);
        log_action($u['id'], 'inv_tags', "{$id};" . implode(',', $tags));
        json_out(['ok'=>true,'investigation'=>$inv]);
      }
    }
    unset($inv);
    json_out(['ok'=>false,'error'=>'Investigation not found'], 404);
  }

  case 'inv_add_entry': {
    $u = require_login();
    require_investigator($u);
    $id = (string)param('id','');
    $text = trim((string)param('text',''));
    $all = load_investigations();
    $file = $_FILES['file'] ?? null;

    foreach ($all as &$inv) {
      if ($inv['id'] !== $id) continue;
      if (!$text && !$file) json_out(['ok'=>false,'error'=>'Message or file required'], 400);

      $entry = [
        'id' => uniqid('entry_', true),
        'ts' => date(DATE_ATOM),
        'author' => investigator_label($u),
      ];

      if ($file && is_array($file) && $file['tmp_name']) {
        if ($file['size'] > 2 * 1024 * 1024) json_out(['ok'=>false,'error'=>'File too large (2MB max)'], 400);
        $mime = mime_content_type($file['tmp_name']) ?: 'application/octet-stream';
        $data = base64_encode((string)file_get_contents($file['tmp_name']));
        $entry['kind'] = 'file';
        $entry['filename'] = clean_name((string)$file['name']);
        $entry['size'] = (int)$file['size'];
        $entry['mime'] = $mime;
        $entry['data_url'] = 'data:' . $mime . ';base64,' . $data;
        if ($text) $entry['text'] = $text;
      } else {
        $entry['kind'] = 'message';
        $entry['text'] = $text;
      }

      $inv['entries'][] = $entry;
      save_investigations($all);
      log_action($u['id'], 'inv_entry', $id);
      json_out(['ok'=>true,'investigation'=>$inv]);
    }
    unset($inv);
    json_out(['ok'=>false,'error'=>'Investigation not found'], 404);
  }

  // ---- logs ----
  case 'logs_list': {
    $u = require_login();
    $limit = (int)param('limit', 200);
    $limit = max(1, min(500, $limit));

    $db = db();
    if (is_ia($u)) {
      $stmt = $db->prepare("
        SELECT l.id, l.user_id, u.username, u.role, l.action, l.meta, l.created_at
        FROM logs l JOIN users u ON u.id=l.user_id
        ORDER BY l.id DESC LIMIT ?
      ");
      $stmt->bind_param("i", $limit);
    } else {
      $stmt = $db->prepare("
        SELECT l.id, l.user_id, u.username, u.role, l.action, l.meta, l.created_at
        FROM logs l JOIN users u ON u.id=l.user_id
        WHERE l.user_id=?
        ORDER BY l.id DESC LIMIT ?
      ");
      $stmt->bind_param("ii", $u['id'], $limit);
    }
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    while ($r = $res->fetch_assoc()) $rows[] = $r;
    $stmt->close();

    json_out(['ok'=>true,'logs'=>$rows]);
  }

  // ---- drive list ----
  case 'list': {
    $u = require_login();
    $parent = param('parent_id', null);
    $parentId = null;
    if ($parent !== null && $parent !== '' && is_numeric((string)$parent)) $parentId = (int)$parent;

    $db = db();
    $items = [];

    if ($parentId === null) {
      if (is_ia($u)) {
        $sql = "SELECT * FROM items WHERE parent_id IS NULL ORDER BY type DESC, name ASC";
        $res = $db->query($sql);
      } else {
        $sql = "SELECT * FROM items WHERE parent_id IS NULL AND (scope='ALL' OR scope=?) ORDER BY type DESC, name ASC";
        $stmt = $db->prepare($sql);
        $role = strtoupper($u['role']);
        $stmt->bind_param("s", $role);
        $stmt->execute();
        $res = $stmt->get_result();
      }
    } else {
      $parentItem = get_item_or_404($parentId);
      if (!can_view_scope($u, (string)$parentItem['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
      if (strtoupper($parentItem['type']) !== 'FOLDER') json_out(['ok'=>false,'error'=>'Not a folder'], 400);

      if (is_ia($u)) {
        $stmt = $db->prepare("SELECT * FROM items WHERE parent_id=? ORDER BY type DESC, name ASC");
        $stmt->bind_param("i", $parentId);
        $stmt->execute();
        $res = $stmt->get_result();
      } else {
        $stmt = $db->prepare("SELECT * FROM items WHERE parent_id=? AND (scope='ALL' OR scope=?) ORDER BY type DESC, name ASC");
        $role = strtoupper($u['role']);
        $stmt->bind_param("is", $parentId, $role);
        $stmt->execute();
        $res = $stmt->get_result();
      }
    }

    while ($r = $res->fetch_assoc()) {
      $canEdit = can_edit_item($u, $r);
      $canDel  = can_delete_item($u, $r);
      $items[] = [
        'id'=>(int)$r['id'],
        'parent_id'=>$r['parent_id'] === null ? null : (int)$r['parent_id'],
        'type'=>$r['type'],
        'name'=>$r['name'],
        'scope'=>$r['scope'],
        'owner_id'=>(int)$r['owner_id'],
        'mime'=>$r['mime'],
        'size'=>$r['size'] === null ? null : (int)$r['size'],
        'updated_at'=>$r['updated_at'],
        'can_edit'=>$canEdit,
        'can_delete'=>$canDel
      ];
    }

    if (isset($stmt) && $stmt instanceof mysqli_stmt) $stmt->close();

    json_out(['ok'=>true,'items'=>$items,'parent_id'=>$parentId]);
  }

  case 'read': {
    $u = require_login();
    $id = (int)param('id', 0);
    if ($id <= 0) json_out(['ok'=>false,'error'=>'Bad id'], 400);

    $item = get_item_or_404($id);
    if (!can_view_scope($u, (string)$item['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
    if (strtoupper($item['type']) !== 'TEXT') json_out(['ok'=>false,'error'=>'Not a text file'], 400);

    log_action($u['id'], 'read', "id={$id};name={$item['name']}");

    json_out(['ok'=>true,'file'=>[
      'id'=>(int)$item['id'],
      'name'=>$item['name'],
      'scope'=>$item['scope'],
      'owner_id'=>(int)$item['owner_id'],
      'content'=>$item['content'] ?? '',
      'can_edit'=>can_edit_item($u, $item),
      'can_delete'=>can_delete_item($u, $item),
    ]]);
  }

  case 'save': {
    $u = require_login();
    $id = (int)param('id', 0);
    $content = (string)param('content', '');
    if ($id <= 0) json_out(['ok'=>false,'error'=>'Bad id'], 400);

    $item = get_item_or_404($id);
    if (!can_view_scope($u, (string)$item['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
    if (strtoupper($item['type']) !== 'TEXT') json_out(['ok'=>false,'error'=>'Not a text file'], 400);
    if (!can_edit_item($u, $item)) json_out(['ok'=>false,'error'=>'Read-only'], 403);

    $db = db();
    $stmt = $db->prepare("UPDATE items SET content=? WHERE id=?");
    $stmt->bind_param("si", $content, $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'save', "id={$id};name={$item['name']}");
    json_out(['ok'=>true]);
  }

  case 'mkdir':
  case 'mktext': {
    $u = require_login();
    $parent = param('parent_id', null);
    $parentId = null;
    if ($parent !== null && $parent !== '' && is_numeric((string)$parent)) $parentId = (int)$parent;

    $name = clean_name((string)param('name',''));
    if (!$name) json_out(['ok'=>false,'error'=>'Missing name'], 400);

    // scope rules:
    // - inside a folder: inherit parent scope (no chaos)
    // - at root: choose (PI/MOOT/IA/ALL) but limited if not IA
    $scopeReq = strtoupper((string)param('scope', strtoupper($u['role'])));
    $scope = $scopeReq;

    $parentScope = get_parent_scope($parentId); // validates folder
    if ($parentScope !== null) {
      // must be allowed to see parent
      $p = get_item_or_404($parentId);
      if (!can_view_scope($u, (string)$p['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
      $scope = $parentScope;
    } else {
      // root create
      if (!is_ia($u)) {
        if (!in_array($scopeReq, [strtoupper($u['role']), 'ALL'], true)) {
          $scope = strtoupper($u['role']);
        }
      } else {
        if (!in_array($scopeReq, ['PI','MOOT','IA','ALL'], true)) $scope = 'ALL';
      }
    }

    $type = ($action === 'mkdir') ? 'FOLDER' : 'TEXT';
    $db = db();

    if ($parentId === null) {
      $stmt = $db->prepare("INSERT INTO items (parent_id, type, name, scope, owner_id, content) VALUES (NULL,?,?,?,?,?)");
      $owner = $u['id'];
      $content = ($type === 'TEXT') ? '' : null;
      $stmt->bind_param("sssis", $type, $name, $scope, $owner, $content);
    } else {
      $stmt = $db->prepare("INSERT INTO items (parent_id, type, name, scope, owner_id, content) VALUES (?,?,?,?,?,?)");
      $owner = $u['id'];
      $content = ($type === 'TEXT') ? '' : null;
      $stmt->bind_param("isssis", $parentId, $type, $name, $scope, $owner, $content);
    }

    $stmt->execute();
    $newId = $stmt->insert_id;
    $stmt->close();

    log_action($u['id'], $type === 'FOLDER' ? 'mkdir' : 'mktext', "id={$newId};name={$name};scope={$scope}");
    json_out(['ok'=>true,'id'=>$newId,'scope'=>$scope,'type'=>$type,'name'=>$name]);
  }

  case 'rename': {
    $u = require_login();
    $id = (int)param('id', 0);
    $name = clean_name((string)param('name',''));
    if ($id <= 0 || !$name) json_out(['ok'=>false,'error'=>'Bad input'], 400);

    $item = get_item_or_404($id);
    if (!can_view_scope($u, (string)$item['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
    if (!can_delete_item($u, $item)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $db = db();
    $stmt = $db->prepare("UPDATE items SET name=? WHERE id=?");
    $stmt->bind_param("si", $name, $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'rename', "id={$id};name={$name}");
    json_out(['ok'=>true]);
  }

  case 'delete': {
    $u = require_login();
    $id = (int)param('id', 0);
    if ($id <= 0) json_out(['ok'=>false,'error'=>'Bad id'], 400);

    $item = get_item_or_404($id);
    if (!can_view_scope($u, (string)$item['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
    if (!can_delete_item($u, $item)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $db = db();

    if (strtoupper($item['type']) === 'FOLDER') {
      $stmt = $db->prepare("SELECT COUNT(*) AS c FROM items WHERE parent_id=?");
      $stmt->bind_param("i", $id);
      $stmt->execute();
      $res = $stmt->get_result()->fetch_assoc();
      $stmt->close();
      if ((int)$res['c'] > 0) json_out(['ok'=>false,'error'=>'Folder not empty'], 400);
    }

    // delete file from disk if upload
    if (strtoupper($item['type']) === 'UPLOAD') {
      $path = (string)$item['storage_path'];
      if ($path && is_file($path)) @unlink($path);
    }

    $stmt = $db->prepare("DELETE FROM items WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'delete', "id={$id};name={$item['name']}");
    json_out(['ok'=>true]);
  }

  case 'upload': {
    $u = require_login();
    if (!isset($_FILES['file'])) json_out(['ok'=>false,'error'=>'No file'], 400);

    $parent = param('parent_id', null);
    $parentId = null;
    if ($parent !== null && $parent !== '' && is_numeric((string)$parent)) $parentId = (int)$parent;

    // scope rules: inside folder inherit; root choose (limited)
    $scopeReq = strtoupper((string)param('scope', strtoupper($u['role'])));
    $scope = $scopeReq;

    $parentScope = null;
    if ($parentId !== null) {
      $p = get_item_or_404($parentId);
      if (!can_view_scope($u, (string)$p['scope'])) json_out(['ok'=>false,'error'=>'Forbidden'], 403);
      if (strtoupper($p['type']) !== 'FOLDER') json_out(['ok'=>false,'error'=>'Parent not folder'], 400);
      $parentScope = strtoupper((string)$p['scope']);
      $scope = $parentScope;
    } else {
      if (!is_ia($u)) {
        if (!in_array($scopeReq, [strtoupper($u['role']), 'ALL'], true)) $scope = strtoupper($u['role']);
      } else {
        if (!in_array($scopeReq, ['PI','MOOT','IA','ALL'], true)) $scope = 'ALL';
      }
    }

    $f = $_FILES['file'];
    if ($f['error'] !== UPLOAD_ERR_OK) json_out(['ok'=>false,'error'=>'Upload error'], 400);
    if ($f['size'] > UPLOAD_MAX_BYTES) json_out(['ok'=>false,'error'=>'File too large'], 400);

    $origName = clean_name((string)$f['name']);
    if (!$origName) $origName = 'upload.bin';

    $mime = (string)($f['type'] ?? 'application/octet-stream');
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
    $safeExt = $ext ? preg_replace('/[^a-z0-9]/', '', $ext) : '';
    $rand = bin2hex(random_bytes(16));
    $fileName = $rand . ($safeExt ? ('.' . $safeExt) : '');

    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0775, true);
    $dest = UPLOAD_DIR . '/' . $fileName;

    if (!move_uploaded_file($f['tmp_name'], $dest)) json_out(['ok'=>false,'error'=>'Cannot store file'], 500);

    $db = db();
    if ($parentId === null) {
      $stmt = $db->prepare("INSERT INTO items (parent_id, type, name, scope, owner_id, storage_path, mime, size) VALUES (NULL,'UPLOAD',?,?,?,?,?,?)");
      $owner = $u['id'];
      $size = (int)$f['size'];
      $stmt->bind_param("ssissi", $origName, $scope, $owner, $dest, $mime, $size);
    } else {
      $stmt = $db->prepare("INSERT INTO items (parent_id, type, name, scope, owner_id, storage_path, mime, size) VALUES (?,'UPLOAD',?,?,?,?,?,?)");
      $owner = $u['id'];
      $size = (int)$f['size'];
      $stmt->bind_param("ississi", $parentId, $origName, $scope, $owner, $dest, $mime, $size);
    }
    $stmt->execute();
    $newId = $stmt->insert_id;
    $stmt->close();

    log_action($u['id'], 'upload', "id={$newId};name={$origName};scope={$scope}");
    json_out(['ok'=>true,'id'=>$newId,'name'=>$origName,'scope'=>$scope]);
  }

  // ---- IA admin ----
  case 'admin_list_users': {
    $u = require_login();
    if (!is_ia($u)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $db = db();
    $res = $db->query("SELECT id, username, role, status, created_at FROM users ORDER BY id ASC");
    $rows = [];
    while ($r = $res->fetch_assoc()) $rows[] = $r;
    json_out(['ok'=>true,'users'=>$rows]);
  }

  case 'admin_create_user': {
    $u = require_login();
    if (!is_ia($u)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $username = strtoupper(trim((string)param('username','')));
    $password = (string)param('password','');
    $role = strtoupper(trim((string)param('role','PI')));

    if (!$username || !$password) json_out(['ok'=>false,'error'=>'Missing fields'], 400);
    if (!in_array($role, ['PI','MOOT','IA'], true)) $role = 'PI';
    if (!preg_match('/^[A-Z0-9_-]{3,32}$/', $username)) json_out(['ok'=>false,'error'=>'Bad username format'], 400);

    $hash = password_hash($password, PASSWORD_DEFAULT);

    $db = db();
    $stmt = $db->prepare("INSERT INTO users (username, pass_hash, role, status) VALUES (?,?,?,'ACTIVE')");
    $stmt->bind_param("sss", $username, $hash, $role);
    $ok = $stmt->execute();
    $err = $stmt->error;
    $newId = $stmt->insert_id;
    $stmt->close();

    if (!$ok) json_out(['ok'=>false,'error'=>'Create failed: '.$err], 400);

    log_action($u['id'], 'admin_create_user', "uid={$newId};username={$username};role={$role}");
    json_out(['ok'=>true,'id'=>$newId]);
  }

  case 'admin_set_status': {
    $u = require_login();
    if (!is_ia($u)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $id = (int)param('id', 0);
    $status = strtoupper((string)param('status','ACTIVE'));
    if ($id <= 0) json_out(['ok'=>false,'error'=>'Bad id'], 400);
    if (!in_array($status, ['ACTIVE','DISABLED'], true)) $status = 'ACTIVE';

    $db = db();
    $stmt = $db->prepare("UPDATE users SET status=? WHERE id=?");
    $stmt->bind_param("si", $status, $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'admin_set_status', "id={$id};status={$status}");
    json_out(['ok'=>true]);
  }

  case 'admin_set_role': {
    $u = require_login();
    if (!is_ia($u)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $id = (int)param('id', 0);
    $role = strtoupper((string)param('role','PI'));
    if ($id <= 0) json_out(['ok'=>false,'error'=>'Bad id'], 400);
    if (!in_array($role, ['PI','MOOT','IA'], true)) $role = 'PI';

    $db = db();
    $stmt = $db->prepare("UPDATE users SET role=? WHERE id=?");
    $stmt->bind_param("si", $role, $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'admin_set_role', "id={$id};role={$role}");
    json_out(['ok'=>true]);
  }

  case 'admin_reset_password': {
    $u = require_login();
    if (!is_ia($u)) json_out(['ok'=>false,'error'=>'Forbidden'], 403);

    $id = (int)param('id', 0);
    $password = (string)param('password','');
    if ($id <= 0 || !$password) json_out(['ok'=>false,'error'=>'Bad input'], 400);

    $hash = password_hash($password, PASSWORD_DEFAULT);

    $db = db();
    $stmt = $db->prepare("UPDATE users SET pass_hash=? WHERE id=?");
    $stmt->bind_param("si", $hash, $id);
    $stmt->execute();
    $stmt->close();

    log_action($u['id'], 'admin_reset_password', "id={$id}");
    json_out(['ok'=>true]);
  }

  default:
    json_out(['ok'=>false,'error'=>'Unknown action'], 400);
}
