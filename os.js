// os.js (PATCHED: no localStorage, session-only auth)
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  // --- tiny safe sessionStorage wrapper (optional UX, not auth)
  const sess = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch {} }
  };

  async function api(action, opts = {}) {
    const { method = 'GET', data = null, form = null } = opts;

    let url = `api.php?action=${encodeURIComponent(action)}`;
    const fetchOpts = { method, credentials: 'include' };

    if (form) {
      fetchOpts.body = form;
    } else if (method !== 'GET' && data) {
      fetchOpts.headers = { 'Content-Type': 'application/json' };
      fetchOpts.body = JSON.stringify({ action, ...data });
    } else if (method === 'GET' && data) {
      const qs = new URLSearchParams(data);
      url += `&${qs.toString()}`;
    }

    const res = await fetch(url, fetchOpts);

    // binary download
    if (action === 'download') return res;

    const json = await res.json().catch(() => ({}));

    if (!res.ok || json.ok === false) {
      const msg = json.error || `API error (${res.status})`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }

    return json;
  }

  async function me() {
    const r = await api('me');
    return r.user;
  }

  async function login(username, password) {
    const r = await api('login', { method: 'POST', data: { username, password } });
    return r.user;
  }

  async function logout(mode = 'logout') {
    await api('logout', { method: 'POST', data: { mode } });
  }

  function routeDesktop(role) {
    role = String(role || '').toUpperCase();
    if (role === 'PI') location.href = 'desktop_pi.html';
    else if (role === 'MOOT') location.href = 'desktop_moot.html';
    else if (role === 'IA') location.href = 'desktop_ia.html';
    else location.href = 'index.html';
  }

  // ---------------- Window manager (generic) ----------------
  function initWindowManager() {
    const tasksEl = $('#tasks');
    const zBase = { z: 10 };
    let dragState = null;
    let resizeState = null;

    function bringToFront(win) {
      zBase.z += 1;
      win.style.zIndex = zBase.z;
      setActiveTask(win.id);
    }

    function ensureTask(winId, title) {
      if (!tasksEl) return null;
      let task = tasksEl.querySelector(`[data-task="${winId}"]`);
      if (!task) {
        task = document.createElement('div');
        task.className = 'task';
        task.dataset.task = winId;
        task.innerHTML = `<span class="task-left"><span class="dot"></span><span class="t"></span></span><span class="hint">CLICK</span>`;
        task.querySelector('.t').textContent = title;
        task.addEventListener('click', () => toggleWindow(winId));
        tasksEl.appendChild(task);
      }
      return task;
    }

    function setActiveTask(winId) {
      $$('.task').forEach(t => t.classList.toggle('active', t.dataset.task === winId));
    }

    function openWindow(winId) {
      const win = document.getElementById(winId);
      if (!win) return;
      win.classList.remove('hidden');
      bringToFront(win);
      const title = win.querySelector('.win-title')?.textContent?.trim() || winId;
      ensureTask(winId, title);
    }

    function closeWindow(winId) {
      const win = document.getElementById(winId);
      if (!win) return;
      win.classList.add('hidden');
      setActiveTask(null);
    }

    function minimizeWindow(winId) {
      const win = document.getElementById(winId);
      if (!win) return;
      win.classList.add('hidden');
    }

    function toggleWindow(winId) {
      const win = document.getElementById(winId);
      if (!win) return;
      const hidden = win.classList.contains('hidden');
      if (hidden) openWindow(winId);
      else minimizeWindow(winId);
    }

    // open from icons / menu
    document.addEventListener('dblclick', (e) => {
      const icon = e.target.closest('.icon[data-open]');
      if (icon) openWindow(icon.dataset.open);
    });

    document.addEventListener('click', (e) => {
      const close = e.target.closest('[data-close]')?.dataset.close;
      if (close) closeWindow(close);
      const min = e.target.closest('[data-min]')?.dataset.min;
      if (min) minimizeWindow(min);

      const open = e.target.closest('[data-open]')?.dataset.open;
      if (open && e.target.closest('#startmenu')) openWindow(open);
    });

    // focus on click
    $$('.window').forEach(w => w.addEventListener('mousedown', () => bringToFront(w)));

    // drag
    document.addEventListener('mousedown', (e) => {
      const titlebar = e.target.closest('[data-drag]');
      if (!titlebar) return;
      if (e.target.closest('.ctl')) return;
      const win = titlebar.closest('.window');
      if (!win) return;

      bringToFront(win);
      const rect = win.getBoundingClientRect();
      dragState = { win, offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top };
    });

    // resize
    document.addEventListener('mousedown', (e) => {
      const handle = e.target.closest('[data-resize]');
      if (!handle) return;
      const win = handle.closest('.window');
      if (!win) return;
      bringToFront(win);

      const rect = win.getBoundingClientRect();
      resizeState = { win, startX: e.clientX, startY: e.clientY, startW: rect.width, startH: rect.height };
      e.preventDefault();
      e.stopPropagation();
    });

    document.addEventListener('mousemove', (e) => {
      if (dragState) {
        const { win, offsetX, offsetY } = dragState;
        const maxX = window.innerWidth - 40;
        const maxY = window.innerHeight - 80;
        let x = e.clientX - offsetX;
        let y = e.clientY - offsetY;
        x = Math.max(18, Math.min(x, maxX));
        y = Math.max(78, Math.min(y, maxY));
        win.style.left = x + 'px';
        win.style.top = y + 'px';
        return;
      }

      if (resizeState) {
        const { win, startX, startY, startW, startH } = resizeState;
        const minW = parseInt(getComputedStyle(win).minWidth || '380', 10);
        const minH = parseInt(getComputedStyle(win).minHeight || '240', 10);

        let newW = startW + (e.clientX - startX);
        let newH = startH + (e.clientY - startY);

        const rect = win.getBoundingClientRect();
        const maxW = window.innerWidth - rect.left - 18;
        const maxH = window.innerHeight - rect.top - 78;

        newW = Math.max(minW, Math.min(newW, maxW));
        newH = Math.max(minH, Math.min(newH, maxH));
        win.style.width = newW + 'px';
        win.style.height = newH + 'px';
      }
    });

    document.addEventListener('mouseup', () => { dragState = null; resizeState = null; });

    // icon selection
    const iconGrid = $('#iconGrid');
    function clearIconSelection() { $$('.icon').forEach(i => i.classList.remove('selected')); }
    if (iconGrid) {
      iconGrid.addEventListener('click', (e) => {
        const icon = e.target.closest('.icon');
        if (!icon) return;
        clearIconSelection();
        icon.classList.add('selected');
      });
    }
    const desktop = $('#desktop');
    if (desktop) {
      desktop.addEventListener('click', (e) => {
        const clickedIcon = e.target.closest('.icon');
        const clickedWindow = e.target.closest('.window');
        const clickedSide = e.target.closest('.side');
        if (!clickedIcon && !clickedWindow && !clickedSide) clearIconSelection();
      });
    }

    // start menu
    const startmenu = $('#startmenu');
    const startbtn = $('#startbtn');
    if (startbtn && startmenu) {
      startbtn.addEventListener('click', () => startmenu.classList.toggle('open'));
      document.addEventListener('click', (e) => {
        const clickedStart = e.target.closest('#startbtn');
        const clickedMenu = e.target.closest('#startmenu');
        if (!clickedStart && !clickedMenu) startmenu.classList.remove('open');
      });
    }

    return { openWindow, closeWindow, minimizeWindow, toggleWindow };
  }

  // ---------------- Drive ----------------
  function initDrive(user, wm) {
    const foldersEl = $('#drive-folders');
    const filesEl = $('#drive-files');
    const pathEl = $('#drive-path');
    const statusEl = $('#drive-status');
    const scopeSel = $('#drive-scope');
    const backBtn = $('#drive-back');
    const newFolderBtn = $('#drive-newfolder');
    const newTextBtn = $('#drive-newtext');
    const uploadBtn = $('#drive-upload');

    const editorTitle = $('#editor-title');
    const editorScope = $('#editor-scope');
    const editorText = $('#editor-text');
    const editorSave = $('#editor-save');
    const editorRename = $('#editor-rename');
    const editorDelete = $('#editor-delete');
    const editorRO = $('#editor-ro');

    let cwd = null;
    let stack = [];
    let openFile = null;

    function setStatus(s) { if (statusEl) statusEl.textContent = s; }

    // scope options
    if (scopeSel) {
      const role = user.role.toUpperCase();
      const opts = (role === 'IA') ? ['PI', 'MOOT', 'IA', 'ALL'] : [role, 'ALL'];
      scopeSel.innerHTML = opts.map(o => `<option value="${o}">${o}</option>`).join('');
      scopeSel.value = role;
    }

    function renderPath() {
      if (!pathEl) return;
      if (cwd === null) pathEl.textContent = 'ROOT';
      else pathEl.textContent = `FOLDER #${cwd}`;
    }

    function itemRow(item, kind) {
      const badge = `<span class="badge">${item.scope}</span>`;
      const right = (kind === 'file')
        ? `<div class="row-actions">
            ${item.type === 'TEXT'
              ? `<button class="mini" data-openfile="${item.id}">OPEN</button>`
              : `<a class="mini" href="api.php?action=download&id=${item.id}" target="_blank" rel="noopener">DL</a>`
            }
            ${item.can_edit ? '' : `<span class="mini ghost">RO</span>`}
            ${item.can_delete ? `<button class="mini" data-rename="${item.id}">REN</button><button class="mini danger" data-del="${item.id}">DEL</button>` : ``}
          </div>`
        : `<div class="row-actions">
            <button class="mini" data-cd="${item.id}">OPEN</button>
            ${item.can_delete ? `<button class="mini" data-rename="${item.id}">REN</button><button class="mini danger" data-del="${item.id}">DEL</button>` : ``}
          </div>`;

      return `
        <div class="drive-row" data-id="${item.id}" data-type="${item.type}">
          <div class="drive-left">
            <div class="drive-name">${kind === 'folder' ? '📁' : (item.type === 'TEXT' ? '📝' : '📦')} ${item.name}</div>
            <div class="drive-sub">#${item.id} • ${item.type} ${badge}</div>
          </div>
          ${right}
        </div>
      `;
    }

    async function refresh() {
      setStatus('Loading…');
      renderPath();
      const r = await api('list', { data: { parent_id: cwd ?? '' } });
      const items = r.items || [];
      const folders = items.filter(x => x.type === 'FOLDER');
      const files = items.filter(x => x.type !== 'FOLDER');

      if (foldersEl) foldersEl.innerHTML = folders.length ? folders.map(f => itemRow(f, 'folder')).join('') : `<div class="empty">No folders.</div>`;
      if (filesEl) filesEl.innerHTML = files.length ? files.map(f => itemRow(f, 'file')).join('') : `<div class="empty">No files.</div>`;
      setStatus(`OK • ${folders.length} folders • ${files.length} files`);
    }

    function cd(id) {
      stack.push(cwd);
      cwd = id;
      refresh().catch(err => setStatus(err.message));
    }

    function back() {
      if (!stack.length) { cwd = null; refresh(); return; }
      cwd = stack.pop();
      refresh().catch(err => setStatus(err.message));
    }

    async function mkdir() {
      const name = prompt('Folder name?');
      if (!name) return;
      const scope = scopeSel?.value || user.role;
      await api('mkdir', { method: 'POST', data: { parent_id: cwd ?? '', name, scope } });
      await refresh();
    }

    async function mktext() {
      const name = prompt('Text file name? (ex: report.txt)');
      if (!name) return;
      const scope = scopeSel?.value || user.role;
      const r = await api('mktext', { method: 'POST', data: { parent_id: cwd ?? '', name, scope } });
      await refresh();
      await openText(r.id);
    }

    async function upload() {
      const input = document.createElement('input');
      input.type = 'file';
      input.onchange = async () => {
        if (!input.files?.length) return;
        const f = input.files[0];
        const fd = new FormData();
        fd.append('action', 'upload');
        fd.append('parent_id', cwd ?? '');
        fd.append('scope', scopeSel?.value || user.role);
        fd.append('file', f);
        try {
          await api('upload', { method: 'POST', form: fd });
          await refresh();
        } catch (e) {
          setStatus(e.message);
        }
      };
      input.click();
    }

    async function openText(id) {
      const r = await api('read', { data: { id } });
      openFile = r.file;

      if (editorTitle) editorTitle.textContent = openFile.name;
      if (editorScope) editorScope.textContent = openFile.scope;
      if (editorText) editorText.value = openFile.content || '';

      const ro = !openFile.can_edit;
      if (editorText) editorText.disabled = ro;
      if (editorSave) editorSave.disabled = ro;
      if (editorRO) editorRO.style.display = ro ? 'inline-block' : 'none';

      if (editorDelete) editorDelete.disabled = !openFile.can_delete;
      if (editorRename) editorRename.disabled = !openFile.can_delete;

      wm.openWindow('win-editor');
    }

    async function saveText() {
      if (!openFile) return;
      await api('save', { method: 'POST', data: { id: openFile.id, content: editorText?.value || '' } });
      setStatus('Saved.');
      await refresh();
    }

    async function renameItem(id) {
      const name = prompt('New name?');
      if (!name) return;
      await api('rename', { method: 'POST', data: { id, name } });
      await refresh();
      if (openFile && openFile.id === id) {
        openFile.name = name;
        if (editorTitle) editorTitle.textContent = name;
      }
    }

    async function deleteItem(id) {
      if (!confirm('Delete this item?')) return;
      await api('delete', { method: 'POST', data: { id } });
      if (openFile && openFile.id === id) {
        openFile = null;
        wm.closeWindow('win-editor');
      }
      await refresh();
    }

    // events
    backBtn?.addEventListener('click', () => back());
    newFolderBtn?.addEventListener('click', () => mkdir().catch(e => setStatus(e.message)));
    newTextBtn?.addEventListener('click', () => mktext().catch(e => setStatus(e.message)));
    uploadBtn?.addEventListener('click', () => upload().catch(e => setStatus(e.message)));

    $('#editor-save')?.addEventListener('click', () => saveText().catch(e => setStatus(e.message)));
    $('#editor-rename')?.addEventListener('click', () => openFile && renameItem(openFile.id).catch(e => setStatus(e.message)));
    $('#editor-delete')?.addEventListener('click', () => openFile && deleteItem(openFile.id).catch(e => setStatus(e.message)));

    document.addEventListener('click', (e) => {
      const cdBtn = e.target.closest('[data-cd]')?.dataset.cd;
      if (cdBtn) cd(parseInt(cdBtn, 10));

      const openBtn = e.target.closest('[data-openfile]')?.dataset.openfile;
      if (openBtn) openText(parseInt(openBtn, 10)).catch(err => setStatus(err.message));

      const ren = e.target.closest('[data-rename]')?.dataset.rename;
      if (ren) renameItem(parseInt(ren, 10)).catch(err => setStatus(err.message));

      const del = e.target.closest('[data-del]')?.dataset.del;
      if (del) deleteItem(parseInt(del, 10)).catch(err => setStatus(err.message));
    });

    refresh().catch(e => setStatus(e.message));
  }

  // ---------------- Logs ----------------
  function initLogs(user) {
    const out = $('#logs-out');
    const q = $('#logs-q');
    const refreshBtn = $('#logs-refresh');

    async function load() {
      const r = await api('logs_list', { data: { limit: 250 } });
      const logs = r.logs || [];
      const needle = (q?.value || '').trim().toLowerCase();

      const lines = logs
        .filter(l => {
          if (!needle) return true;
          return String(l.action).toLowerCase().includes(needle)
            || String(l.meta || '').toLowerCase().includes(needle)
            || String(l.username || '').toLowerCase().includes(needle);
        })
        .map(l => `[${l.created_at}] ${l.username}(${l.role}) • ${l.action}${l.meta ? ` • ${l.meta}` : ''}`);

      if (out) out.textContent = lines.length ? lines.join('\n') : 'No logs.';
    }

    refreshBtn?.addEventListener('click', () => load().catch(e => out && (out.textContent = e.message)));
    q?.addEventListener('keypress', (e) => { if (e.key === 'Enter') load().catch(err => out && (out.textContent = err.message)); });

    load().catch(e => out && (out.textContent = e.message));
  }

  // ---------------- IA Admin ----------------
  function initAdmin(user) {
    if (user.role.toUpperCase() !== 'IA') return;

    const listEl = $('#admin-users');
    const createBtn = $('#admin-create');
    const uName = $('#admin-username');
    const uPass = $('#admin-password');
    const uRole = $('#admin-role');

    if (!listEl) return;

    async function refresh() {
      const r = await api('admin_list_users');
      const users = r.users || [];
      listEl.innerHTML = users.map(u => `
        <div class="admin-row">
          <div class="admin-left">
            <div class="admin-name">${u.username} <span class="badge">${u.role}</span> <span class="badge ${u.status === 'DISABLED' ? 'danger' : ''}">${u.status}</span></div>
            <div class="admin-sub">#${u.id} • created ${u.created_at}</div>
          </div>
          <div class="admin-actions">
            <select class="mini" data-setrole="${u.id}">
              ${['PI','MOOT','IA'].map(r => `<option value="${r}" ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}
            </select>
            <select class="mini" data-setstatus="${u.id}">
              ${['ACTIVE','DISABLED'].map(s => `<option value="${s}" ${s === u.status ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
            <button class="mini" data-reset="${u.id}">RESET PW</button>
          </div>
        </div>
      `).join('') || '<div class="empty">No users.</div>';
    }

    createBtn?.addEventListener('click', async () => {
      const username = (uName?.value || '').trim().toUpperCase();
      const password = (uPass?.value || '').trim();
      const role = (uRole?.value || 'PI').trim().toUpperCase();
      if (!username || !password) return alert('Username & password required.');
      await api('admin_create_user', { method: 'POST', data: { username, password, role } });
      if (uName) uName.value = '';
      if (uPass) uPass.value = '';
      await refresh();
    });

    document.addEventListener('change', async (e) => {
      const setRole = e.target.closest('[data-setrole]')?.dataset.setrole;
      if (setRole) {
        await api('admin_set_role', { method: 'POST', data: { id: parseInt(setRole, 10), role: e.target.value } });
        await refresh();
      }
      const setStatus = e.target.closest('[data-setstatus]')?.dataset.setstatus;
      if (setStatus) {
        await api('admin_set_status', { method: 'POST', data: { id: parseInt(setStatus, 10), status: e.target.value } });
        await refresh();
      }
    });

    document.addEventListener('click', async (e) => {
      const reset = e.target.closest('[data-reset]')?.dataset.reset;
      if (!reset) return;
      const pw = prompt('New password?');
      if (!pw) return;
      await api('admin_reset_password', { method: 'POST', data: { id: parseInt(reset, 10), password: pw } });
      alert('Password reset.');
    });

    refresh().catch(err => listEl.textContent = err.message);
  }

  // ---------------- MOOT Comms (saves to Drive as TEXT at root) ----------------
  function initMootModules(user, wm) {
    if (user.role.toUpperCase() !== 'MOOT') return;

    const genBtn = $('#comms-generate');
    const saveBtn = $('#comms-save');
    const clearBtn = $('#comms-clear');
    const out = $('#comms-out');

    const to = $('#comms-to');
    const topic = $('#comms-topic');
    const body = $('#comms-body');

    function obfuscate(s) {
      const shifted = s.split('').map(ch => {
        const code = ch.charCodeAt(0);
        if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + 7) % 26) + 65);
        if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + 7) % 26) + 97);
        return ch;
      }).join('');
      return btoa(unescape(encodeURIComponent(shifted)));
    }

    let lastPayload = '';

    genBtn?.addEventListener('click', () => {
      const payload =
`TO:${(to?.value || 'HQ-OPS').trim()}
TOPIC:${(topic?.value || 'SITREP').trim()}
TIME:${new Date().toISOString()}
SIG:${user.username}
CLEARANCE:MOOT
---
${(body?.value || '').trim()}`;
      lastPayload = payload;
      if (out) out.textContent = obfuscate(payload);
    });

    saveBtn?.addEventListener('click', async () => {
      if (!lastPayload) return alert('Generate first.');
      const name = `dispatch_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
      const mk = await api('mktext', { method: 'POST', data: { parent_id: '', name, scope: 'MOOT' } });
      const content = `ENCODED:\n${out?.textContent || ''}\n\nDECODED:\n${lastPayload}\n`;
      await api('save', { method: 'POST', data: { id: mk.id, content } });
      alert(`Saved to Drive: ${name}`);
      wm.openWindow('win-drive');
    });

    clearBtn?.addEventListener('click', () => {
      if (to) to.value = '';
      if (topic) topic.value = '';
      if (body) body.value = '';
      if (out) out.textContent = 'No content yet…';
      lastPayload = '';
    });
  }

  // ---------------- Scratchpad (all roles) ----------------
  function initScratchpad(user, wm) {
    const area = $('#note-text');
    if (!area) return;

    const status = $('#note-status');
    const saveSessionBtn = $('#note-save-session');
    const loadSessionBtn = $('#note-load-session');
    const saveDriveBtn = $('#note-save-drive');
    const clearBtn = $('#note-clear');
    const insertBtn = $('#note-insert-ts');

    const key = `note_${user.username}_${user.role}`;
    let debounceTimer = null;

    function setStatus(msg) { if (status) status.textContent = msg; }

    function loadSession() {
      const saved = sess.get(key) || '';
      area.value = saved;
      setStatus(saved ? 'Loaded session notes.' : 'No notes yet.');
    }

    function saveSession() {
      sess.set(key, area.value);
      setStatus('Saved locally for this session.');
    }

    function insertTimestamp() {
      const prefix = area.value.trim() ? '\n' : '';
      area.value = `${area.value}${prefix}[${new Date().toISOString()}] `;
      saveSession();
      area.focus();
    }

    async function saveToDrive() {
      const safeContent = area.value || 'No notes.';
      const name = `notes_${user.username}_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
      const mk = await api('mktext', { method: 'POST', data: { parent_id: '', name, scope: String(user.role).toUpperCase() } });
      await api('save', { method: 'POST', data: { id: mk.id, content: safeContent } });
      setStatus(`Saved to Drive as ${name}`);
      wm.openWindow('win-drive');
    }

    function clearNotes() {
      area.value = '';
      saveSession();
    }

    area.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(saveSession, 500);
    });

    saveSessionBtn?.addEventListener('click', () => saveSession());
    loadSessionBtn?.addEventListener('click', () => loadSession());
    saveDriveBtn?.addEventListener('click', () => saveToDrive().catch(e => setStatus(e.message)));
    clearBtn?.addEventListener('click', () => clearNotes());
    insertBtn?.addEventListener('click', () => insertTimestamp());

    loadSession();
  }

  // ---------------- Investigations (PI + IA) ----------------
  function initInvestigations(user) {
    const wrap = $('#win-investigations');
    if (!wrap) return;

    const listEl = $('#inv-list');
    const listEmpty = $('#inv-list-empty');
    const titleEl = $('#inv-active-title');
    const tagDisplay = $('#inv-tag-display');
    const tagInput = $('#inv-tags');
    const tagSave = $('#inv-save-tags');
    const entriesEl = $('#inv-entries');
    const statusEl = $('#inv-status');
    const countEl = $('#inv-count');
    const activeMeta = $('#inv-active-meta');
    const newTitle = $('#inv-new-title');
    const newTags = $('#inv-new-tags');
    const createBtn = $('#inv-create');
    const entryText = $('#inv-entry-text');
    const entryFile = $('#inv-entry-file');
    const addEntryBtn = $('#inv-add-entry');
    const exportBtn = $('#inv-export');
    const filterInput = $('#inv-filter');
    const filterApply = $('#inv-apply-filter');
    const filterClear = $('#inv-clear-filter');

    const key = `investigations_${user.username}_${user.role}`;
    let investigations = [];
    let currentId = null;

    function setStatus(msg) { if (statusEl) statusEl.textContent = msg; }

    function authorLabel() {
      const role = String(user.role || '').toUpperCase();
      if (role === 'PI' || role === 'IA') return `Investigator ${user.username}`;
      return `Agent ${user.username}`;
    }

    function formatText(txt) {
      return (txt || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\n/g, '<br>');
    }

    function parseTags(val) {
      return (val || '')
        .split(',')
        .map(t => t.trim())
        .filter(Boolean)
        .slice(0, 12);
    }

    function load() {
      try {
        const raw = sess.get(key);
        investigations = raw ? JSON.parse(raw) : [];
      } catch { investigations = []; }
    }

    function persist() {
      sess.set(key, JSON.stringify(investigations));
    }

    function renderList() {
      if (!listEl) return;
      const q = (filterInput?.value || '').trim().toLowerCase();
      const filtered = investigations.filter(inv => {
        if (!q) return true;
        const hay = `${inv.title} ${(inv.tags || []).join(' ')}`.toLowerCase();
        return hay.includes(q);
      });

      const cards = filtered.map(inv => `
        <div class="inv-card ${inv.id === currentId ? 'active' : ''}" data-inv="${inv.id}">
          <div class="inv-card-title">${inv.title}</div>
          <div class="inv-card-tags">${inv.tags?.length ? inv.tags.join(' • ') : 'No tags'}</div>
          <div class="inv-meta">${inv.entries?.length || 0} entries • opened by ${inv.created_by || 'Unknown'}</div>
        </div>
      `);
      listEl.innerHTML = cards.join('');
      if (listEmpty) listEmpty.style.display = filtered.length ? 'none' : 'block';
      if (countEl) countEl.textContent = `${filtered.length}/${investigations.length || 0} investigations`;
      if (listEmpty && !filtered.length) {
        listEmpty.textContent = investigations.length ? 'No matching investigations.' : 'No investigations yet.';
      }
      const cards = investigations.map(inv => `
        <div class="inv-card ${inv.id === currentId ? 'active' : ''}" data-inv="${inv.id}">
          <div class="inv-card-title">${inv.title}</div>
          <div class="inv-card-tags">${inv.tags?.length ? inv.tags.join(' • ') : 'No tags'}</div>
          <div class="inv-meta">${inv.entries?.length || 0} entries</div>
        </div>
      `);
      listEl.innerHTML = cards.join('');
      if (listEmpty) listEmpty.style.display = investigations.length ? 'none' : 'block';
    }

    function renderTags(inv) {
      if (!tagDisplay) return;
      if (!inv || !inv.tags?.length) {
        tagDisplay.innerHTML = '<div class="inv-empty">No tags yet.</div>';
        if (tagInput) tagInput.value = '';
        return;
      }
      tagDisplay.innerHTML = inv.tags.map(t => `<span class="inv-pill">${t}</span>`).join('');
      if (tagInput) tagInput.value = inv.tags.join(', ');
    }

    function renderEntries(inv) {
      if (!entriesEl) return;
      if (!inv) {
        entriesEl.innerHTML = '<div class="inv-empty">Select or create an investigation.</div>';
        return;
      }
      if (!inv.entries?.length) {
        entriesEl.innerHTML = '<div class="inv-empty">No entries yet — add a message or file.</div>';
        return;
      }

      const rows = (inv.entries || [])
        .slice()
        .sort((a, b) => new Date(a.ts || 0) - new Date(b.ts || 0))
        .map(e => {
        const when = new Date(e.ts || Date.now()).toLocaleString();
        const head = `<div class="inv-entry-head"><span class="inv-entry-title">${e.kind === 'file' ? 'File Upload' : 'Message'}</span><span>${when} • ${e.author || 'Unknown'}</span></div>`;
        const bodyParts = [];
        if (e.text) bodyParts.push(`<div class="inv-entry-body">${formatText(e.text)}</div>`);
      const rows = inv.entries.map(e => {
        const when = new Date(e.ts || Date.now()).toLocaleString();
        const head = `<div class="inv-entry-head"><span class="inv-entry-title">${e.kind === 'file' ? 'File Upload' : 'Message'}</span><span>${when} • ${e.author || 'Unknown'}</span></div>`;
        const bodyParts = [];
        if (e.text) bodyParts.push(`<div class="inv-entry-body">${e.text.replace(/</g, '&lt;')}</div>`);
        if (e.kind === 'file' && e.url) {
          const size = e.size ? ` (${Math.round(e.size/1024)} KB)` : '';
          bodyParts.push(`<div class="inv-entry-body inv-inline"><span class="chip">FILE</span> <a class="inv-file" href="${e.url}" download="${e.filename || 'file'}" target="_blank" rel="noopener">${e.filename || 'Download'}${size}</a></div>`);
        }
        return `<div class="inv-entry">${head}${bodyParts.join('')}</div>`;
      });

      entriesEl.innerHTML = rows.join('');
    }

    function renderActive() {
      const inv = investigations.find(x => x.id === currentId) || null;
      if (titleEl) titleEl.textContent = inv ? inv.title : 'No investigation selected';
      renderTags(inv);
      renderEntries(inv);
      if (activeMeta) {
        if (!inv) activeMeta.textContent = 'Waiting for selection…';
        else {
          const opened = inv.created_at ? new Date(inv.created_at).toLocaleString() : 'Unknown date';
          const entryCount = inv.entries?.length || 0;
          const tagLabel = inv.tags?.length ? `${inv.tags.length} tag(s)` : 'No tags';
          activeMeta.textContent = `Opened by ${inv.created_by || 'Unknown'} • ${opened} • ${entryCount} entries • ${tagLabel}`;
        }
      }
    }

    function select(id) {
      currentId = id;
      renderList();
      renderActive();
    }

    function create() {
      const title = (newTitle?.value || '').trim();
      if (!title) { setStatus('Title required.'); return; }
      const tags = parseTags(newTags?.value || '');
      const inv = { id: Date.now(), title, tags, entries: [], created_at: new Date().toISOString(), created_by: authorLabel() };
      const inv = { id: Date.now(), title, tags, entries: [], created_at: new Date().toISOString() };
      investigations.unshift(inv);
      persist();
      select(inv.id);
      if (newTitle) newTitle.value = '';
      if (newTags) newTags.value = '';
      setStatus('Investigation created.');
    }

    function saveTags() {
      const inv = investigations.find(x => x.id === currentId);
      if (!inv) { setStatus('Select an investigation first.'); return; }
      inv.tags = parseTags(tagInput?.value || '');
      persist();
      renderList();
      renderTags(inv);
      setStatus('Tags updated.');
    }

    function addEntry() {
      const inv = investigations.find(x => x.id === currentId);
      if (!inv) { setStatus('Select an investigation first.'); return; }
      const text = (entryText?.value || '').trim();
      const file = entryFile?.files?.[0];
      if (!text && !file) { setStatus('Add a message or attach a file.'); return; }

      if (file && file.size > 2 * 1024 * 1024) {
        setStatus('File too large for thread (limit 2MB).');
        return;
      }

      const ts = new Date().toISOString();
      const author = authorLabel();

      const pushEntry = (payload) => {
        inv.entries.push({ id: Date.now(), ts, author, ...payload });
        persist();
        renderEntries(inv);
        renderList();
        if (entryText) entryText.value = '';
        if (entryFile) entryFile.value = '';
        setStatus('Entry added.');
      };

      if (file) {
        setStatus('Reading file…');
        const reader = new FileReader();
        reader.onload = () => {
          pushEntry({ kind: 'file', filename: file.name, size: file.size, url: reader.result, text });
        };
        reader.onerror = () => setStatus('Failed to read file.');
        reader.readAsDataURL(file);
        return;
      }

      pushEntry({ kind: 'message', text });
    }

    listEl?.addEventListener('click', (e) => {
      const card = e.target.closest('[data-inv]');
      if (!card) return;
      select(parseInt(card.dataset.inv, 10));
    });
    createBtn?.addEventListener('click', () => create());
    tagSave?.addEventListener('click', () => saveTags());
    addEntryBtn?.addEventListener('click', () => addEntry());
    filterApply?.addEventListener('click', () => renderList());
    filterClear?.addEventListener('click', () => { if (filterInput) filterInput.value = ''; renderList(); });
    exportBtn?.addEventListener('click', () => {
      const inv = investigations.find(x => x.id === currentId);
      if (!inv) { setStatus('Select an investigation first.'); return; }
      const lines = [];
      lines.push(`INVESTIGATION: ${inv.title}`);
      lines.push(`Opened by: ${inv.created_by || 'Unknown'} on ${new Date(inv.created_at || Date.now()).toLocaleString()}`);
      lines.push(`Tags: ${inv.tags?.join(', ') || 'none'}`);
      lines.push('--- TIMELINE ---');
      const sorted = (inv.entries || []).slice().sort((a, b) => new Date(a.ts || 0) - new Date(b.ts || 0));
      sorted.forEach((e, idx) => {
        const when = new Date(e.ts || Date.now()).toLocaleString();
        const head = `[${idx + 1}] ${when} • ${e.author || 'Unknown'} • ${e.kind === 'file' ? 'FILE' : 'MESSAGE'}`;
        lines.push(head);
        if (e.filename) lines.push(`File: ${e.filename} (${e.size ? Math.round(e.size/1024) + ' KB' : 'unknown'})`);
        if (e.text) lines.push(e.text);
        lines.push('');
      });
      const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${inv.title.replace(/[^a-z0-9_-]+/gi, '_') || 'investigation'}_thread.txt`;
      a.click();
      URL.revokeObjectURL(url);
      setStatus('Exported thread.');
    });

    load();
    renderList();
    renderActive();
    setStatus('Waiting…');
  }

  // ---------------- Boot Desktop ----------------
  // Supports: bootDesktop("PI") OR bootDesktop("PI", userFromDesktop)
  async function bootDesktop(requiredRole, userOverride = null) {
    let user = userOverride;

    if (!user) {
      user = await me().catch(() => null);
    }
    if (!user) {
      location.href = 'index.html';
      return;
    }

    const role = String(user.role || '').toUpperCase();
    if (requiredRole && role !== String(requiredRole).toUpperCase()) {
      routeDesktop(role);
      return;
    }

    // time HUD
    function pad(n) { return String(n).padStart(2, '0'); }
    function format(d) {
      return `${pad(d.getMonth() + 1)}/${pad(d.getDate())}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
    function tick() {
      const now = new Date();
      const hud = $('#hud-time');
      const tray = $('#tray-time');
      if (hud) hud.textContent = format(now);
      if (tray) tray.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    }
    tick(); setInterval(tick, 1000);

    // identity
    if ($('#agent-name')) $('#agent-name').textContent = user.username;
    if ($('#tray-agent')) {
      const label = (role === 'MOOT') ? 'CALLSIGN' : (role === 'IA') ? 'INVESTIGATOR' : 'AGENT';
      $('#tray-agent').textContent = `${label}: ${user.username}`;
    }

    const wm = initWindowManager();
    initDrive(user, wm);
    initLogs(user);
    initAdmin(user);
    initMootModules(user, wm);
    initInvestigations(user);
    initScratchpad(user, wm);

    // lock/logout (server session only)
    const doExit = async (mode) => {
      try { await logout(mode); } catch {}
      location.href = 'index.html';
    };
    $('#btn-lock')?.addEventListener('click', () => doExit('lock'));
    $('#btn-logout')?.addEventListener('click', () => doExit('logout'));
    $('#menu-lock')?.addEventListener('click', () => doExit('lock'));
    $('#menu-logout')?.addEventListener('click', () => doExit('logout'));

    // default open drive once per TAB (sessionStorage, not auth)
    const k = `fbi_first_${role}`;
    if (!sess.get(k)) {
      sess.set(k, '1');
      wm.openWindow('win-drive');
    }

    // if your desktop hides body until auth, reveal here too
    document.body.style.visibility = 'visible';
  }

  window.FBIOS = { api, me, login, logout, bootDesktop, routeDesktop };
})();
