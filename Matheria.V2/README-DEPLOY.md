# Matheria V2 deployment

## GitHub
1. Create a **private** GitHub repository named `Matheria` (recommended because this is a game with account functionality).
2. Upload the contents of this folder to the repository root. Keep `server.js`, `package.json`, and the `public/` folder at the top level.
3. Do not commit `data/users.json`, `data/secret.txt`, passwords, tokens, or other private data. The `.gitignore` file excludes the runtime account database and server secret.

## Render
1. In Render, create a **Web Service** and connect this GitHub repository.
2. Choose the Node runtime.
3. Build command: `npm install`
4. Start command: `npm start`
5. Deploy. The app listens on Render's `PORT` environment variable automatically.

The Node server serves the game page and its `/api/` and WebSocket endpoints from the same service, so use the Render service URL as the game URL. Do not use GitHub Pages for this project; GitHub Pages cannot run `server.js` or its WebSocket server.

## Important data note
The original archive included a `data/users.json` account database and `data/secret.txt`. They are deliberately not included in this deploy-ready copy to avoid publishing account data or a signing secret. The server creates a fresh secret and empty account database on first start. Existing accounts will therefore not be present in this copy.

For real ongoing use, configure persistent storage for the Render service and set `DATA_DIR` to the mounted disk path (for example `/var/data`). Without persistent storage, accounts and saved progress may be lost when the hosting service restarts or is redeployed. Keep the secret file on that same persistent disk so existing login tokens remain valid.
