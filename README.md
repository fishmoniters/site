# fish moniters

A static page plus a tiny Node server (no dependencies). The server is what makes the admin code, uploads and blog work for everyone.

## run it
    node server.js          # http://localhost:3000

Needs Node 18+. On first start it creates `data/` (gallery.json, posts.json, uploads/) and seeds your 6 works plus a "hello world" post (delete it in admin mode).

## admin mode
Click the lock (top left) and enter the code. The code only exists in `server.js` (default `1937`), is checked on the server, and never reaches the browser. 5 wrong tries locks that visitor out for 1 min, doubling each time.
If your repo is public, set the `ADMIN_CODE` environment variable on your host instead so it isn't in the source.

## hosting
It must run on a host that can run Node and keep files: Render, Railway, Fly.io, a VPS, a Raspberry Pi. GitHub Pages / Netlify static hosting cannot do this.
- Set `TRUST_PROXY=1` when behind a proxy (Render, Railway, Fly, nginx) so lockouts are per visitor.
- Put `data/` on a persistent disk/volume (or set `DATA_DIR`), otherwise uploads and posts vanish on redeploy. Back it up by copying that folder.
- Use https so the login cookie is marked Secure.
