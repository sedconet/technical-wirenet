'use strict';
require('./env');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { db, audit } = require('./db');
const S = require('./security');

authenticator.options = { window: 1, step: 30 };
const ARGON = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const ISSUER = process.env.TOTP_ISSUER || 'WireNet Technical';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback'); // behind nginx on same host

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"], fontSrc: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"],
      baseUri: ["'none'"], objectSrc: ["'none'"],
    },
  },
  hsts: S.PROD ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  crossOriginEmbedderPolicy: true,
  referrerPolicy: { policy: 'no-referrer' },
  xFrameOptions: { action: 'deny' },
}));
app.use((req, res, next) => {
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  next();
});
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(S.loadSession);
app.use('/api', S.csrfProtect);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' } });
const mfaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' } });

// --------------------------------------------------------------- pages
const page = (f) => (req, res) => res.sendFile(path.join(PUBLIC_DIR, f));
app.get('/login', (req, res) => (req.session && req.session.stage === 'full' ? res.redirect('/') : page('login.html')(req, res)));
app.get('/', (req, res) => (req.session && req.session.stage === 'full' ? page('index.html')(req, res) : res.redirect('/login')));
app.get('/manage', (req, res) => {
  if (!req.session || req.session.stage !== 'full') return res.redirect('/login');
  if (req.user.role === 'viewer') return res.redirect('/');
  page('manage.html')(req, res);
});
app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets'), { index: false, fallthrough: false }));
app.get('/favicon.ico', (req, res) => res.redirect(301, '/assets/favicon.svg'));
app.get('/healthz', (req, res) => res.type('text').send('ok'));

// --------------------------------------------------------------- auth
let DUMMY_HASH;
argon2.hash('dummy-password-for-timing', ARGON).then((h) => { DUMMY_HASH = h; });

const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

app.post('/api/login', loginLimiter, async (req, res) => {
  const username = str(req.body.username, 64);
  const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
  const generic = { error: 'Incorrect username or password.' };
  const u = username ? db.prepare('SELECT * FROM users WHERE username = ?').get(username) : null;

  if (!u) { await argon2.verify(DUMMY_HASH, password || 'x').catch(() => {}); audit(req, 'login_fail', `unknown:${username}`); return res.status(401).json(generic); }
  if (u.disabled) { await argon2.verify(DUMMY_HASH, 'x').catch(() => {}); return res.status(401).json(generic); }
  if (u.locked_until > Date.now()) { audit(req, 'login_locked', null, u); return res.status(423).json({ error: 'Account temporarily locked. Try again in 15 minutes or contact an administrator.' }); }

  const ok = await argon2.verify(u.password_hash, password).catch(() => false);
  if (!ok) {
    const fails = u.failed_attempts + 1;
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
      .run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0, u.id);
    audit(req, fails >= MAX_FAILS ? 'account_locked' : 'login_fail', null, u);
    return res.status(401).json(generic);
  }
  if (argon2.needsRehash(u.password_hash, ARGON)) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await argon2.hash(password, ARGON), u.id);
  }
  // Password OK -> second factor is ALWAYS required. Not yet enrolled -> must enrol now.
  const stage = u.totp_secret_enc ? 'mfa' : 'enroll';
  const csrf = S.createSession(req, res, u.id, stage);
  res.json({ next: stage, csrf });
});

function verifyTotp(user, code) {
  if (!/^\d{6}$/.test(code)) return false;
  const secret = S.decrypt(user.totp_secret_enc);
  const delta = authenticator.checkDelta(code, secret);
  if (delta === null) return false;
  const step = Math.floor(Date.now() / 30000) + delta;
  if (step <= (user.totp_last_step || 0)) return false; // replay protection
  db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  return true;
}

function completeLogin(req, res, u) {
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = ? WHERE id = ?').run(Date.now(), u.id);
  const csrf = S.createSession(req, res, u.id, 'full'); // fresh token after MFA
  audit(req, 'login_ok', null, u);
  res.json({ ok: true, csrf });
}

app.post('/api/login/mfa', mfaLimiter, S.requireStage('mfa'), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user_id);
  if (!verifyTotp(u, str(req.body.code, 6))) {
    const fails = u.failed_attempts + 1;
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
      .run(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0, u.id);
    audit(req, 'mfa_fail', null, u);
    if (fails >= MAX_FAILS) S.destroySession(req, res);
    return res.status(401).json({ error: 'That code is not valid.' });
  }
  completeLogin(req, res, u);
});

const pendingSecrets = new Map(); // sessionHash -> secret (enrolment only, short lived)
app.get('/api/mfa/setup', S.requireStage('enroll'), async (req, res) => {
  let secret = pendingSecrets.get(req.session.id_hash);
  if (!secret) { secret = authenticator.generateSecret(20); pendingSecrets.set(req.session.id_hash, secret); setTimeout(() => pendingSecrets.delete(req.session.id_hash), 6 * 60 * 1000).unref(); }
  const uri = authenticator.keyuri(req.user.username, ISSUER, secret);
  res.json({ qr: await QRCode.toDataURL(uri, { margin: 1, width: 220 }), secret });
});
app.post('/api/mfa/enroll', mfaLimiter, S.requireStage('enroll'), (req, res) => {
  const secret = pendingSecrets.get(req.session.id_hash);
  const code = str(req.body.code, 6);
  if (!secret || !/^\d{6}$/.test(code) || authenticator.checkDelta(code, secret) === null) {
    return res.status(400).json({ error: 'That code is not valid. Check your phone clock and try again.' });
  }
  pendingSecrets.delete(req.session.id_hash);
  db.prepare('UPDATE users SET totp_secret_enc = ?, totp_last_step = ? WHERE id = ?')
    .run(S.encrypt(secret), Math.floor(Date.now() / 30000) + 1, req.session.user_id);
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user_id);
  audit(req, 'mfa_enrolled', null, u);
  completeLogin(req, res, u);
});

app.post('/api/logout', (req, res) => { if (req.user) audit(req, 'logout'); S.destroySession(req, res); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session || req.session.stage !== 'full') return res.status(401).json({ error: 'Not signed in' });
  res.json({ user: req.user, csrf: req.session.csrf_token });
});

app.post('/api/me/password', S.requireAuth(), async (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await argon2.verify(u.password_hash, String(req.body.current || '')).catch(() => false))) return res.status(400).json({ error: 'Current password is incorrect.' });
  const err = S.passwordPolicy(req.body.next);
  if (err) return res.status(400).json({ error: err });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await argon2.hash(req.body.next, ARGON), u.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash != ?').run(u.id, req.session.id_hash); // sign out elsewhere
  audit(req, 'password_changed');
  res.json({ ok: true });
});

// --------------------------------------------------------------- tasks
const CATEGORIES = (process.env.TASK_CATEGORIES || 'Networking,Structured Cabling,Wireless,Security & CCTV,Cloud & Microsoft 365,Servers & Virtualisation,Cybersecurity,Telephony & VoIP,Support & Maintenance,Other').split(',').map((s) => s.trim());

function publicTask(t, role) {
  const out = {
    id: t.id, title: t.title, category: t.category, location: t.location, summary: t.summary,
    technologies: t.technologies ? t.technologies.split(',').map((s) => s.trim()).filter(Boolean) : [],
    completed_on: t.completed_on, client: t.show_client ? t.client : null,
  };
  if (role !== 'viewer') Object.assign(out, { client: t.client, show_client: !!t.show_client, published: !!t.published, updated_at: t.updated_at });
  return out;
}

function validateTask(b) {
  const t = {
    title: str(b.title, 160), category: str(b.category, 60), client: str(b.client, 120) || null,
    show_client: b.show_client ? 1 : 0, location: str(b.location, 120) || null, summary: str(b.summary, 3000),
    technologies: Array.isArray(b.technologies) ? b.technologies.map((s) => str(s, 40)).filter(Boolean).slice(0, 20).join(',') : str(b.technologies, 800),
    completed_on: str(b.completed_on, 10), published: b.published === false ? 0 : 1,
  };
  if (!t.title) return { error: 'Title is required.' };
  if (!CATEGORIES.includes(t.category)) return { error: 'Choose a valid category.' };
  if (!t.summary) return { error: 'Summary is required.' };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t.completed_on) || isNaN(Date.parse(t.completed_on))) return { error: 'Completion date must be a valid date.' };
  if (t.completed_on > new Date().toISOString().slice(0, 10)) return { error: 'Completion date cannot be in the future.' };
  return { t };
}

app.get('/api/categories', S.requireAuth(), (req, res) => res.json(CATEGORIES));

app.get('/api/tasks', S.requireAuth(), (req, res) => {
  const rows = req.user.role === 'viewer'
    ? db.prepare('SELECT * FROM tasks WHERE published = 1 ORDER BY completed_on DESC, id DESC').all()
    : db.prepare('SELECT * FROM tasks ORDER BY completed_on DESC, id DESC').all();
  res.json(rows.map((t) => publicTask(t, req.user.role)));
});

app.post('/api/tasks', S.requireAuth('editor'), (req, res) => {
  const { t, error } = validateTask(req.body || {});
  if (error) return res.status(400).json({ error });
  const now = Date.now();
  const r = db.prepare(`INSERT INTO tasks (title,category,client,show_client,location,summary,technologies,completed_on,published,created_by,created_at,updated_at)
    VALUES (@title,@category,@client,@show_client,@location,@summary,@technologies,@completed_on,@published,@uid,@now,@now)`)
    .run({ ...t, uid: req.user.id, now });
  audit(req, 'task_create', `#${r.lastInsertRowid} ${t.title}`);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.put('/api/tasks/:id', S.requireAuth('editor'), (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare('SELECT id FROM tasks WHERE id = ?').get(id)) return res.status(404).json({ error: 'Not found' });
  const { t, error } = validateTask(req.body || {});
  if (error) return res.status(400).json({ error });
  db.prepare(`UPDATE tasks SET title=@title,category=@category,client=@client,show_client=@show_client,location=@location,
    summary=@summary,technologies=@technologies,completed_on=@completed_on,published=@published,updated_at=@now WHERE id=@id`)
    .run({ ...t, now: Date.now(), id });
  audit(req, 'task_update', `#${id} ${t.title}`);
  res.json({ ok: true });
});

app.delete('/api/tasks/:id', S.requireAuth('editor'), (req, res) => {
  const id = Number(req.params.id);
  const r = db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  audit(req, 'task_delete', `#${id}`);
  res.json({ ok: true });
});

// --------------------------------------------------------------- users (admin)
app.get('/api/users', S.requireAuth('admin'), (req, res) => {
  res.json(db.prepare(`SELECT id,username,display_name,role,disabled,last_login_at,created_at,
    (totp_secret_enc IS NOT NULL) AS mfa, (locked_until > ?) AS locked FROM users ORDER BY username`).all(Date.now()));
});

app.post('/api/users', S.requireAuth('admin'), async (req, res) => {
  const username = str(req.body.username, 64).toLowerCase();
  const display = str(req.body.display_name, 100) || username;
  const role = ['admin', 'editor', 'viewer'].includes(req.body.role) ? req.body.role : null;
  if (!/^[a-z0-9._@-]{3,64}$/.test(username)) return res.status(400).json({ error: 'Username: 3-64 chars, letters, numbers, . _ - @' });
  if (!role) return res.status(400).json({ error: 'Choose a role.' });
  const err = S.passwordPolicy(req.body.password);
  if (err) return res.status(400).json({ error: err });
  try {
    db.prepare('INSERT INTO users (username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
      .run(username, display, await argon2.hash(req.body.password, ARGON), role, Date.now());
  } catch (e) { return res.status(409).json({ error: 'That username already exists.' }); }
  audit(req, 'user_create', `${username} (${role})`);
  res.status(201).json({ ok: true });
});

app.patch('/api/users/:id', S.requireAuth('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  if (id === req.user.id && (b.disabled || (b.role && b.role !== 'admin'))) return res.status(400).json({ error: 'You cannot disable or demote yourself.' });
  if (b.role && ['admin', 'editor', 'viewer'].includes(b.role)) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(b.role, id);
  if (typeof b.disabled === 'boolean') db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(b.disabled ? 1 : 0, id);
  if (b.unlock) db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?').run(id);
  if (b.reset_mfa) db.prepare('UPDATE users SET totp_secret_enc = NULL, totp_last_step = 0 WHERE id = ?').run(id);
  if (b.password) {
    const err = S.passwordPolicy(b.password);
    if (err) return res.status(400).json({ error: err });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await argon2.hash(b.password, ARGON), id);
  }
  if (b.disabled || b.reset_mfa || b.password || b.role) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id); // force re-login
  audit(req, 'user_update', `${u.username}: ${Object.keys(b).filter((k) => k !== 'password').join(',')}${b.password ? ',password' : ''}`);
  res.json({ ok: true });
});

app.get('/api/audit', S.requireAuth('admin'), (req, res) => {
  res.json(db.prepare('SELECT at,username,action,detail,ip FROM audit_log ORDER BY id DESC LIMIT 200').all());
});

// --------------------------------------------------------------- errors
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((req, res) => res.status(404).type('text').send('Not found'));
app.use((err, req, res, next) => { // never leak stack traces
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(err.status && err.status < 500 ? err.status : 500).json({ error: err.status === 404 ? 'Not found' : 'Something went wrong.' });
});

// Housekeeping: purge expired sessions hourly
setInterval(() => db.prepare('DELETE FROM sessions WHERE last_seen_at < ?').run(Date.now() - 9 * 3600 * 1000), 3600 * 1000).unref();

S.encrypt('selftest'); // fail fast if TOTP_ENC_KEY is missing/invalid
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => console.log(`Technical catalogue listening on http://${HOST}:${PORT}`));
