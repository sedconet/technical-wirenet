'use strict';
const crypto = require('crypto');
const { db } = require('./db');

const PROD = process.env.NODE_ENV === 'production';

// Cookie: __Host- prefix forces Secure, Path=/, no Domain -> cannot be set/read by other *.wirenet.ie hosts.
const COOKIE = PROD ? '__Host-tw_sid' : 'tw_sid';
const IDLE_MS = (Number(process.env.SESSION_IDLE_MINUTES) || 30) * 60 * 1000;
const ABSOLUTE_MS = (Number(process.env.SESSION_MAX_HOURS) || 8) * 3600 * 1000;
const PREAUTH_MS = 5 * 60 * 1000;

// ---------- TOTP secret encryption at rest (AES-256-GCM) ----------
function encKey() {
  const hex = process.env.TOTP_ENC_KEY || '';
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error('TOTP_ENC_KEY must be 64 hex chars (32 bytes). Generate: openssl rand -hex 32');
  }
  return Buffer.from(hex, 'hex');
}
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}
function decrypt(blob) {
  const [iv, tag, ct] = blob.split('.').map((s) => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// ---------- Sessions (opaque random token; only its SHA-256 is stored) ----------
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function createSession(req, res, userId, stage) {
  // Remove any previous session from this browser (prevents session fixation)
  const old = req.cookies && req.cookies[COOKIE];
  if (old) db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(sha256(old));

  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  db.prepare(`INSERT INTO sessions (id_hash,user_id,stage,csrf_token,created_at,last_seen_at,ip,user_agent)
              VALUES (?,?,?,?,?,?,?,?)`)
    .run(sha256(token), userId, stage, csrf, now, now, req.ip, String(req.get('user-agent') || '').slice(0, 200));
  res.cookie(COOKIE, token, {
    httpOnly: true, secure: PROD, sameSite: 'strict', path: '/',
    maxAge: stage === 'full' ? ABSOLUTE_MS : PREAUTH_MS,
  });
  return csrf;
}

function destroySession(req, res) {
  const t = req.cookies && req.cookies[COOKIE];
  if (t) db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(sha256(t));
  res.clearCookie(COOKIE, { httpOnly: true, secure: PROD, sameSite: 'strict', path: '/' });
}

function loadSession(req, res, next) {
  req.session = null; req.user = null;
  const t = req.cookies && req.cookies[COOKIE];
  if (!t) return next();
  const s = db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(sha256(t));
  if (!s) return next();
  const now = Date.now();
  const limit = s.stage === 'full'
    ? (now - s.last_seen_at > IDLE_MS || now - s.created_at > ABSOLUTE_MS)
    : (now - s.created_at > PREAUTH_MS);
  const u = db.prepare('SELECT id,username,display_name,role,disabled,totp_secret_enc FROM users WHERE id = ?').get(s.user_id);
  if (limit || !u || u.disabled) {
    db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(s.id_hash);
    return next();
  }
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now, s.id_hash);
  req.session = s;
  req.user = { id: u.id, username: u.username, display_name: u.display_name, role: u.role, mfa: !!u.totp_secret_enc };
  next();
}

// ---------- CSRF: synchroniser token in header + Origin check ----------
function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  const expected = process.env.PUBLIC_ORIGIN; // e.g. https://technical.wirenet.ie
  if (origin && expected && origin !== expected) return res.status(403).json({ error: 'Bad origin' });
  if (req.session) {
    const sent = req.get('x-csrf-token') || '';
    const a = Buffer.from(sent), b = Buffer.from(req.session.csrf_token);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

const ROLE_RANK = { viewer: 1, editor: 2, admin: 3 };
function requireAuth(minRole = 'viewer') {
  return (req, res, next) => {
    if (!req.session || req.session.stage !== 'full') return res.status(401).json({ error: 'Not signed in' });
    if (ROLE_RANK[req.user.role] < ROLE_RANK[minRole]) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
function requireStage(stage) {
  return (req, res, next) => {
    if (!req.session || req.session.stage !== stage) return res.status(401).json({ error: 'Session expired, sign in again' });
    next();
  };
}

function passwordPolicy(pw) {
  if (typeof pw !== 'string' || pw.length < 12) return 'Password must be at least 12 characters.';
  if (pw.length > 200) return 'Password too long.';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) return 'Use upper case, lower case and a number.';
  return null;
}

module.exports = {
  PROD, COOKIE, encrypt, decrypt, createSession, destroySession, loadSession,
  csrfProtect, requireAuth, requireStage, passwordPolicy, sha256,
};
