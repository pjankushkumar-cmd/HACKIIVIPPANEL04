const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const SESSION_TTL = 12 * 60 * 60 * 1000;
const sessions = new Map();
const ROOT = __dirname;
const COOKIE = 'hackie_session';

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function parseCookies(header='') {
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function send(res, status, body, headers={}) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 8192) { reject(new Error('Request too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function sessionFor(req) {
  const token = parseCookies(req.headers.cookie || '')[COOKIE];
  const entry = token && sessions.get(token);
  if (!entry) return null;
  if (entry.expires < Date.now()) { sessions.delete(token); return null; }
  entry.expires = Date.now() + SESSION_TTL;
  return {token, entry};
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname === '/api/login' && req.method === 'POST') {
    if (!ADMIN_KEY) return send(res, 503, {ok:false,error:'ADMIN_KEY is not configured on the server.'});
    try {
      const body = await readBody(req);
      if (typeof body.key !== 'string' || !safeEqual(body.key, ADMIN_KEY)) {
        return send(res, 401, {ok:false,error:'Invalid access key.'});
      }
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, {created:Date.now(),expires:Date.now()+SESSION_TTL});
      return send(res, 200, {ok:true}, {
        'Set-Cookie': `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL/1000)}`
      });
    } catch {
      return send(res, 400, {ok:false,error:'Invalid request.'});
    }
  }
  if (url.pathname === '/api/session' && req.method === 'GET') {
    const session = sessionFor(req);
    return send(res, session ? 200 : 401, {ok:!!session});
  }
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const session = sessionFor(req);
    if (session) sessions.delete(session.token);
    return send(res, 200, {ok:true}, {'Set-Cookie':`${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
  }
  if (url.pathname.startsWith('/api/')) return send(res, 404, {ok:false,error:'Not found'});
  // Static assets are served from the project root. No public/ directory is used.
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/') pathname = '/index.html';
  const file = path.resolve(ROOT, '.' + pathname);
  if (!file.startsWith(ROOT + path.sep) && file !== path.join(ROOT,'index.html')) {
    res.writeHead(403); return res.end('Forbidden');
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(file).toLowerCase();
    const types = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp'};
    res.writeHead(200, {'Content-Type':types[ext] || 'application/octet-stream','Cache-Control':ext==='.html'?'no-store':'public, max-age=3600'});
    res.end(data);
  });
});
server.listen(PORT, () => {
  console.log(`HACKIE PANEL running on port ${PORT}`);
  if (!ADMIN_KEY) console.warn('WARNING: ADMIN_KEY is missing. Login is disabled until configured.');
});
