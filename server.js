'use strict';
/* fish moniters: tiny zero-dependency server.
   - the admin code is checked HERE and never sent to the browser
   - blog posts + gallery live in ./data (json) and ./data/uploads (images)  */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = process.env.DATA_DIR || path.join(ROOT, 'data');
const UPLOADS = path.join(DATA, 'uploads');
const ADMIN_CODE = String(process.env.ADMIN_CODE || '1937');   // set ADMIN_CODE on your host to keep it out of the repo
const TRUST_PROXY = process.env.TRUST_PROXY === '1';           // set to 1 on Render/Railway/Fly/etc
const SESSION_MS = 7 * 24 * 3600 * 1000;
const MAX_UPLOAD = 15 * 1024 * 1024;

fs.mkdirSync(UPLOADS, { recursive: true });

/* ---------- storage ---------- */
const file = n => path.join(DATA, n + '.json');
function load(n, def) { try { return JSON.parse(fs.readFileSync(file(n), 'utf8')); } catch { return def; } }
function save(n, v) { const t = file(n) + '.tmp'; fs.writeFileSync(t, JSON.stringify(v, null, 2)); fs.renameSync(t, file(n)); }
const uid = () => Date.now().toString(36) + crypto.randomBytes(3).toString('hex');

let gallery = load('gallery', null);
if (!gallery) {
  const w = (id, t, k) => ({ id, src: `/assets/work/${id}.webp`, title: t, kind: k, created: Date.now() });
  gallery = [w('fish2', 'fish²', 'logo'), w('tau', 'tau', 'logo'), w('apateon', 'apateon', 'logo'), w('pfp', 'pfp', 'logo'),
             w('atomic', 'atomic', 'thumb'), w('paymenow', 'paymenow', 'thumb')];
  save('gallery', gallery);
}
let posts = load('posts', null);
if (!posts) {
  posts = [{ id: uid(), title: 'hello world', cover: '/assets/work/atomic.webp', draft: false, createdAt: Date.now(), updatedAt: Date.now(),
    body: "welcome to the blog. everything here is written in **markdown**.\n\n## what works\n\n- **bold**, *italic*, ~~strikethrough~~ and `inline code`\n- [links](https://github.com/fishmoniters)\n- images, lists, tables, quotes and code blocks\n\n> log in with the lock in the top left corner to write your own posts.\n\n```kotlin\nfun main() {\n    println(\"hi\")\n}\n```\n\n![one of my thumbnails](/assets/work/paymenow.webp)\n\n| thing | status |\n|---|---|\n| blog | working |\n| gallery | working |\n" }];
  save('posts', posts);
}

/* ---------- auth ---------- */
let SECRET; try { SECRET = fs.readFileSync(path.join(DATA, '.secret'), 'utf8'); } catch {
  SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(path.join(DATA, '.secret'), SECRET, { mode: 0o600 });
}
const b64 = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const makeToken = () => { const p = b64(JSON.stringify({ exp: Date.now() + SESSION_MS, n: crypto.randomBytes(8).toString('hex') })); return p + '.' + sign(p); };
function safeEq(a, b) { const x = crypto.createHash('sha256').update(String(a)).digest(), y = crypto.createHash('sha256').update(String(b)).digest(); return crypto.timingSafeEqual(x, y); }
function cookies(req) { const o = {}; (req.headers.cookie || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = c.slice(i + 1).trim(); }); return o; }
function isAdmin(req) {
  const t = cookies(req).fm_session; if (!t) return false;
  const [p, s] = t.split('.'); if (!p || !s || !safeEq(sign(p), s)) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
const tries = new Map(); let globalFails = [];
function lockLeft(ip) {
  const now = Date.now(); globalFails = globalFails.filter(t => now - t < 3600e3);
  if (globalFails.length >= 200) return Math.ceil((globalFails[0] + 3600e3 - now) / 1000);
  const r = tries.get(ip); return r && r.until > now ? Math.ceil((r.until - now) / 1000) : 0;
}
function fail(ip) {
  const r = tries.get(ip) || { n: 0, until: 0 }; r.n++; globalFails.push(Date.now());
  if (r.n >= 5) r.until = Date.now() + Math.min(3600e3, 60e3 * 2 ** (r.n - 5));   // 1m, 2m, 4m ... max 1h
  tries.set(ip, r);
  return Math.max(0, 5 - r.n);
}

/* ---------- helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.webp': 'image/webp', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function send(res, code, body, headers = {}) { res.writeHead(code, headers); res.end(body); }
const json = (res, d, code = 200) => send(res, code, JSON.stringify(d), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
function readBody(req, limit) {
  return new Promise((ok, no) => {
    const a = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > limit) { no(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else a.push(c); });
    req.on('end', () => ok(Buffer.concat(a))); req.on('error', no);
  });
}
const readJson = async (req, lim = 1e6) => { try { return JSON.parse((await readBody(req, lim)).toString() || '{}'); } catch (e) { throw e.status ? e : Object.assign(new Error('bad json'), { status: 400 }); } };
function sniff(b) {
  if (b.length > 12 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  if (b.slice(0, 4).toString() === 'GIF8') return 'gif';
  if (b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}
const okSrc = s => typeof s === 'string' && s.length < 500 && (/^\/(uploads|assets)\/[\w.\-\/]+$/.test(s) && !s.includes('..') || /^https:\/\//.test(s));
const clip = (s, n) => String(s ?? '').slice(0, n);
function unused(src) {
  if (!src.startsWith('/uploads/')) return false;
  return !gallery.some(g => g.src === src) && !posts.some(p => p.cover === src || p.body.includes(src));
}
function dropFile(src) { if (unused(src)) fs.unlink(path.join(UPLOADS, path.basename(src)), () => {}); }

/* ---------- api ---------- */
async function api(req, res, p) {
  const m = req.method;
  if (p === '/api/me') return json(res, { admin: isAdmin(req) });
  if (p === '/api/gallery' && m === 'GET') return json(res, { items: gallery });
  if (p === '/api/posts' && m === 'GET') {
    const a = isAdmin(req);
    return json(res, { items: posts.filter(x => a || !x.draft).sort((x, y) => y.createdAt - x.createdAt) });
  }
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'fish') return json(res, { error: 'bad request' }, 403);   // csrf guard

  if (p === '/api/login' && m === 'POST') {
    const ip = ipOf(req), left = lockLeft(ip);
    if (left) return json(res, { error: 'locked', retry: left }, 429);
    const { code } = await readJson(req, 1000);
    if (typeof code === 'string' && safeEq(code, ADMIN_CODE)) {
      tries.delete(ip);
      res.setHeader('Set-Cookie', `fm_session=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted ? '; Secure' : ''}`);
      return json(res, { ok: true });
    }
    const remaining = fail(ip);
    return json(res, { error: 'wrong', remaining }, 401);
  }
  if (p === '/api/logout' && m === 'POST') { res.setHeader('Set-Cookie', 'fm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return json(res, { ok: true }); }

  if (!isAdmin(req)) return json(res, { error: 'not admin' }, 401);

  if (p === '/api/upload' && m === 'POST') {
    const buf = await readBody(req, MAX_UPLOAD), ext = sniff(buf);
    if (!ext) return json(res, { error: 'png, jpg, gif or webp only' }, 415);
    const name = uid() + '.' + ext; fs.writeFileSync(path.join(UPLOADS, name), buf);
    return json(res, { src: '/uploads/' + name });
  }
  let mt;
  if (p === '/api/gallery' && m === 'POST') {
    const b = await readJson(req);
    if (!okSrc(b.src)) return json(res, { error: 'bad image' }, 400);
    const it = { id: uid(), src: b.src, title: clip(b.title, 80) || 'untitled', kind: b.kind === 'thumb' ? 'thumb' : 'logo', created: Date.now() };
    gallery.push(it); save('gallery', gallery); return json(res, it);
  }
  if ((mt = p.match(/^\/api\/gallery\/([\w-]+)$/))) {
    const i = gallery.findIndex(g => g.id === mt[1]); if (i < 0) return json(res, { error: 'not found' }, 404);
    if (m === 'PATCH') { const b = await readJson(req); if (b.title !== undefined) gallery[i].title = clip(b.title, 80) || 'untitled'; if (b.kind) gallery[i].kind = b.kind === 'thumb' ? 'thumb' : 'logo'; save('gallery', gallery); return json(res, gallery[i]); }
    if (m === 'DELETE') { const [g] = gallery.splice(i, 1); save('gallery', gallery); dropFile(g.src); return json(res, { ok: true }); }
  }
  if (p === '/api/posts' && m === 'POST') {
    const b = await readJson(req, 2e6);
    if (!clip(b.title, 200).trim()) return json(res, { error: 'title needed' }, 400);
    const t = Date.now(), it = { id: uid(), title: clip(b.title, 200).trim(), body: clip(b.body, 200000), cover: okSrc(b.cover) ? b.cover : '', draft: !!b.draft, createdAt: t, updatedAt: t };
    posts.push(it); save('posts', posts); return json(res, it);
  }
  if ((mt = p.match(/^\/api\/posts\/([\w-]+)$/))) {
    const i = posts.findIndex(x => x.id === mt[1]); if (i < 0) return json(res, { error: 'not found' }, 404);
    if (m === 'PUT') {
      const b = await readJson(req, 2e6), old = posts[i];
      if (!clip(b.title, 200).trim()) return json(res, { error: 'title needed' }, 400);
      posts[i] = { ...old, title: clip(b.title, 200).trim(), body: clip(b.body, 200000), cover: okSrc(b.cover) ? b.cover : '', draft: !!b.draft, updatedAt: Date.now() };
      save('posts', posts); if (old.cover !== posts[i].cover) dropFile(old.cover); return json(res, posts[i]);
    }
    if (m === 'DELETE') { const [x] = posts.splice(i, 1); save('posts', posts); dropFile(x.cover); return json(res, { ok: true }); }
  }
  return json(res, { error: 'not found' }, 404);
}

/* ---------- static (whitelist: index.html, /assets, /uploads only) ---------- */
function serveFile(req, res, f, cache) {
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) return send(res, 404, 'not found', { 'Content-Type': 'text/plain' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size, 'Cache-Control': cache });
    fs.createReadStream(f).pipe(res);
  });
}
const CSP = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Content-Security-Policy', CSP);
  try {
    let p; try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { return send(res, 400, 'bad'); }
    if (p.startsWith('/api/')) return await api(req, res, p);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'no');
    if (p === '/' || p === '/index.html') return serveFile(req, res, path.join(ROOT, 'index.html'), 'no-cache');
    const base = p.startsWith('/uploads/') ? UPLOADS : p.startsWith('/assets/') ? path.join(ROOT, 'assets') : null;
    if (!base) return send(res, 404, 'not found', { 'Content-Type': 'text/plain' });
    const f = path.join(base, p.replace(/^\/(uploads|assets)\//, ''));
    if (!f.startsWith(base + path.sep)) return send(res, 403, 'no');
    return serveFile(req, res, f, p.startsWith('/uploads/') ? 'public, max-age=31536000, immutable' : 'public, max-age=86400');
  } catch (e) {
    if (!res.headersSent) json(res, { error: e.status ? e.message : 'server error' }, e.status || 500);
    if (!e.status) console.error(e);
  }
}).listen(PORT, () => {
  console.log('site running on http://localhost:' + PORT);
  if (!process.env.ADMIN_CODE) console.log('note: using the built-in admin code. set the ADMIN_CODE env var if your repo is public.');
});
