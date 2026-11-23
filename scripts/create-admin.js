'use strict';
// Usage: node scripts/create-admin.js <username> "<Display Name>"
// Prompts for a password (not echoed). The user enrols an authenticator app on first sign-in.
require('../src/env');
const argon2 = require('argon2');
const readline = require('readline');
const { db } = require('../src/db');
const { passwordPolicy } = require('../src/security');

const [username, display] = process.argv.slice(2);
if (!username) { console.error('Usage: node scripts/create-admin.js <username> "<Display Name>"'); process.exit(1); }

function ask(q) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(q)) rl.output.write(s); };
    rl.question(q, (a) => { rl.close(); process.stdout.write('\n'); resolve(a); });
  });
}
(async () => {
  const pw = process.env.ADMIN_PASSWORD || await ask('Password: ');
  const err = passwordPolicy(pw);
  if (err) { console.error(err); process.exit(1); }
  const hash = await argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
  db.prepare('INSERT INTO users (username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)')
    .run(username.toLowerCase(), display || username, hash, 'admin', Date.now());
  console.log(`Admin "${username}" created. Sign in and scan the QR code with an authenticator app.`);
})().catch((e) => { console.error(e.message); process.exit(1); });
