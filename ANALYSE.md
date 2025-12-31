# Analyse du dépôt FBIuiu

Ce dépôt contient une application web simulant un environnement "FBI OS" avec une page de connexion et plusieurs bureaux thématiques (PI, MOOT, IA). Voici un résumé des principaux fichiers et de leurs rôles.

## Fichiers racine
- **README.md** : bref descriptif du dépôt.
- **index.html** : page de connexion avec formulaire utilisateur/mot de passe, mise en page sombre et messages d'état. Elle s'appuie sur `os.js` pour gérer l'authentification (vérification de session active, appel à l'API puis redirection vers le bureau selon le rôle). Les styles sont intégrés en ligne.
- **os.js** : cœur côté client. Fournit un client API (`api`, `login`, `logout`, `me`, `routeDesktop`), un gestionnaire de fenêtres (drag, resize, tâches, icônes, menu démarrer) et des modules métiers (Drive avec navigation, création/édition/suppression, upload et lecture de fichiers texte, éditeur de texte, vue des logs, etc.). Utilise `sessionStorage` uniquement pour du confort, l'authentification repose sur la session serveur.
- **config.php** : paramètres de connexion MySQL, nom de session et configuration de stockage des uploads (répertoire, limite 5 Mo).
- **api.php** : routeur backend pour l'API JSON/ téléchargements. Gère l'authentification (login/logout/me), la consultation des logs, le CRUD sur dossiers/fichiers (texte ou upload) avec contrôles de droits selon rôle/scope, les lectures/écritures de texte et le téléchargement de fichiers téléversés. Les actions sont journalisées en base via `log_action`.

## Bureaux et styles
- **desktop_base.css** : thème commun (couleurs, grille de fond, HUD, fenêtres, boutons, barres de tâches, composants Drive/éditeur/logs).
- **desktop_pi.css**, **desktop_moot.css**, **desktop_ia.css** : personnalisations visuelles propres à chaque bureau (couleurs secondaires, ombrages, arrière-plans et badges de rôle).
- **desktop_pi.html**, **desktop_moot.html**, **desktop_ia.html** : pages bureau pour chaque rôle. Toutes chargent `desktop_base.css` + une feuille spécifique, initialisent le HUD (nom d’agent, horloge), affichent des icônes pour ouvrir les modules Drive/éditeur/logs, et contiennent la structure des fenêtres (gestion via `os.js`).

## Autres éléments
- **desktop_pi.css**, **desktop_moot.css**, **desktop_ia.css** partagent la même structure de fenêtres et s’appuient sur les mêmes IDs/classes que `os.js` attend (ex. `win-drive`, `tasks`, `startmenu`).
- **api.php** attend une base MySQL et un dossier `storage/uploads` (mentionné mais absent par défaut) pour stocker les fichiers téléversés.

En résumé, l’application combine une UI type OS (HTML/CSS/JS) et une API PHP pour l’authentification, la journalisation et la gestion de fichiers avec contrôles de rôle/scope.
