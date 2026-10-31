const express = require('express');
const session = require('express-session');
const openid = require('openid');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const BASE = process.env.BASE_URL || `http://localhost:${PORT}`;
const SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  console.error('SESSION_SECRET باید تنظیم شود (فایل .env.example را ببین)');
  process.exit(1);
}

const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
let db = {};
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const saveDb = () => fs.writeFile(FILE, JSON.stringify(db), () => {});

// ورود با Steam OpenID بدون نیاز به API Key
const rp = new openid.RelyingParty(BASE + '/auth/steam/return', BASE + '/', true, false, []);

// اسم و عکس را از پروفایل عمومی می‌گیرد؛ اگر پروفایل خصوصی بود اسم پیش‌فرض می‌ماند
async function getProfile(id) {
  const u = { id, name: 'Steam ' + id.slice(-4), avatar: '' };
  try {
    const t = await (await fetch('https://steamcommunity.com/profiles/' + id + '?xml=1', { signal: AbortSignal.timeout(5000) })).text();
    const n = /<steamID><!\[CDATA\[(.*?)\]\]><\/steamID>/.exec(t);
    const a = /<avatarMedium><!\[CDATA\[(.*?)\]\]><\/avatarMedium>/.exec(t);
    if (n && n[1]) u.name = n[1];
    if (a && a[1].startsWith('https://')) u.avatar = a[1];
  } catch (e) {}
  return u;
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(session({
  secret: SECRET, resave: false, saveUninitialized: false,
  cookie: { maxAge: 30 * 864e5, httpOnly: true, sameSite: 'lax', secure: BASE.startsWith('https') }
}));

app.get('/auth/steam', (q, r) =>
  rp.authenticate('https://steamcommunity.com/openid', false, (e, url) => (e || !url ? r.redirect('/') : r.redirect(url))));

app.get('/auth/steam/return', (q, r) =>
  rp.verifyAssertion(q, async (e, res) => {
    const m = res && res.authenticated && /^https?:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/.exec(res.claimedIdentifier || '');
    if (e || !m) return r.redirect('/');
    q.session.user = await getProfile(m[1]);
    r.redirect('/');
  }));

app.get('/logout', (q, r) => q.session.destroy(() => r.redirect('/')));

app.get('/api/me', (q, r) => {
  const u = q.session.user;
  r.json(u ? { user: u, state: db[u.id] || null } : { user: null });
});

app.post('/api/state', (q, r) => {
  const u = q.session.user;
  if (!u) return r.status(401).end();
  const s = q.body;
  if (!s || typeof s.b !== 'number' || !isFinite(s.b) || s.b < 0 || !Array.isArray(s.inv) ||
      s.inv.length > 500 || !s.inv.every(i => Number.isInteger(i) && i >= 0 && i < 14)) {
    return r.status(400).end();
  }
  db[u.id] = { b: s.b, inv: s.inv };
  saveDb();
  r.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log('http://localhost:' + PORT));
