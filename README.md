# WireNet Technical: completed task catalogue

A small, self-hosted web app for **technical.wirenet.ie**. It has three parts:

* **Catalogue** (`/`): the page shown to prospective customers. It lists completed tasks, newest first, grouped by year. Visitors can search, filter by service area and year, and print or save it as a PDF.
* **Manage** (`/manage`): where staff add, edit, unpublish and delete tasks. Admins also manage users here and can read the activity log.
* **Sign-in** (`/login`): username and password, then a **mandatory** 6-digit authenticator code. There is no anonymous access to anything.

| Role   | Can do |
|--------|--------|
| viewer | Read published tasks. Client names appear only where "Show client name" is ticked. Give prospects this role. |
| editor | Everything a viewer can, plus add, edit and delete tasks and see drafts. |
| admin  | Everything an editor can, plus manage users, unlock accounts, reset 2FA and view the activity log. |

---

## Recommended authentication for technical.wirenet.ie

The site will hold client work history and be shown to outsiders, so use **two layers**: an identity-aware gateway in front, plus the app's own MFA login behind it.

### Layer 1 (recommended): identity-aware proxy / SSO with phishing-resistant MFA

Put the site behind a gateway that authenticates people **before any traffic reaches the server**. Two good fits:

1. **Microsoft Entra ID**, if WireNet uses Microsoft 365. Publish the app through **Entra Application Proxy**, or require Entra sign-in at the gateway. Then:
   * Staff sign in with their existing M365 accounts. Use **Conditional Access** to require **phishing-resistant MFA** (passkeys or FIDO2 keys, Windows Hello for Business, or Microsoft Authenticator with number matching) and to block legacy auth.
   * Invite prospects as **B2B guest users** with an access review or expiry date. They get access only to this app.
2. **Cloudflare Zero Trust Access**, if you'd rather not depend on M365. Create an Access application for `technical.wirenet.ie` with:
   * A staff policy that uses your IdP (Entra, Google Workspace or Okta) with MFA.
   * A prospect policy that uses an **email one-time PIN** for named addresses only, with a short session (for example 24 h).
   * Origin locked down with a Cloudflare Tunnel so the server has **no open inbound ports**.

Either option gives you central offboarding, device and location rules, sign-in logs and protection against password spraying, without building any of it yourself.

### Layer 2 (included in this app): local accounts with mandatory TOTP

This app's own login is still required behind the gateway, as defence in depth. It is also safe to run on its own if you skip Layer 1.

| Control | Implementation |
|---|---|
| Password storage | Argon2id (OWASP parameters), automatic rehash, minimum 12 characters with mixed case and a digit |
| Second factor | TOTP (RFC 6238) is **compulsory**. Users enrol by QR code on first sign-in. Secrets are encrypted at rest with AES-256-GCM. Codes cannot be replayed. |
| Brute force | Per-IP rate limits on password and code endpoints. The account locks for 15 min after 5 failures. Unknown users get the same timing and the same message. |
| Sessions | 256-bit random token, and only its SHA-256 is stored server-side. `__Host-` cookie with `HttpOnly`, `Secure` and `SameSite=Strict`. The token is rotated after MFA. 30 min idle and 8 h absolute timeouts. A password change or admin reset signs the user out everywhere. |
| CSRF | Per-session synchroniser token in a header, plus an `Origin` check, plus SameSite=Strict |
| XSS / clickjacking | Strict CSP (`default-src 'none'`, no inline script or style). The DOM is built with `textContent` only. `X-Frame-Options: DENY` and `frame-ancestors 'none'`. |
| Transport | HSTS (2 years, preload), TLS 1.2+ only at nginx, app bound to 127.0.0.1 |
| Privacy | `noindex` on every page, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| Audit | Sign-ins, failures, lockouts and every task or user change are logged with user and IP (Manage → Activity log) |

**Why not SMS codes or passwords alone?** Passwords alone fall to phishing and credential stuffing. SMS codes are vulnerable to SIM-swap and interception. Authenticator-app TOTP is a strong baseline. Passkeys or FIDO2 keys through Layer 1 are the strongest option because they cannot be phished.

---

## Deploy (Ubuntu/Debian server)

```bash
# 1. Prerequisites
sudo apt install -y nginx sqlite3 certbot python3-certbot-nginx
# Node.js 20.12+ (22 LTS recommended), e.g. from NodeSource

# 2. App user and folders
sudo useradd --system --home /opt/technical-wirenet --shell /usr/sbin/nologin technical
sudo mkdir -p /opt/technical-wirenet /var/lib/technical-wirenet
sudo cp -r . /opt/technical-wirenet && cd /opt/technical-wirenet
sudo npm ci --omit=dev
sudo chown -R root:root /opt/technical-wirenet
sudo chown technical:technical /var/lib/technical-wirenet && sudo chmod 700 /var/lib/technical-wirenet

# 3. Configuration
sudo cp .env.example .env
sudo sed -i "s/^TOTP_ENC_KEY=.*/TOTP_ENC_KEY=$(openssl rand -hex 32)/" .env
sudo chown root:technical .env && sudo chmod 640 .env
# Keep a copy of TOTP_ENC_KEY in your password manager: without it, all users must re-enrol 2FA.

# 4. First admin (you'll be asked for a password)
sudo -u technical node scripts/create-admin.js yourname "Your Name"

# 5. Service + reverse proxy + TLS
sudo cp deploy/technical-wirenet.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now technical-wirenet
sudo cp deploy/nginx-technical.wirenet.ie.conf /etc/nginx/sites-available/technical.wirenet.ie
sudo ln -s /etc/nginx/sites-available/technical.wirenet.ie /etc/nginx/sites-enabled/
sudo certbot --nginx -d technical.wirenet.ie
sudo nginx -t && sudo systemctl reload nginx

# 6. Nightly backup
echo "15 2 * * * root /opt/technical-wirenet/deploy/backup.sh" | sudo tee /etc/cron.d/technical-wirenet
```

DNS: add an `A` (and optionally `AAAA`) record for `technical.wirenet.ie` pointing to the server. If you use Cloudflare Tunnel, create a tunnel route instead.

Then go to https://technical.wirenet.ie, sign in, scan the QR code and start adding tasks under **Manage**.

## Day-to-day

* **Add a completed task:** Manage → Tasks. Untick *Published* to save it as a draft.
* **Give a prospect access:** Manage → Users → Invite, role **Viewer**. Use *Generate password* and send the password by phone or SMS, separately from the username. Disable the account when the sales conversation ends.
* **Lost phone:** an admin clicks *Reset 2FA*. The user re-enrols at their next sign-in.
* **Show a customer in person:** sign in with a viewer account so drafts and hidden client names never appear on screen.
* **Change categories:** set `TASK_CATEGORIES` in `.env` and restart the service.

## Local development

```bash
npm install
printf "NODE_ENV=development\nTOTP_ENC_KEY=$(openssl rand -hex 32)\nPUBLIC_ORIGIN=http://127.0.0.1:3000\n" > .env
node scripts/create-admin.js admin "Admin"
npm start   # http://127.0.0.1:3000
```

## Files

```
src/server.js        routes, auth flow, task + user API
src/security.js      sessions, CSRF, encryption, role checks, password policy
src/db.js            SQLite schema + audit helper
public/              login, catalogue and manage pages (no inline JS/CSS)
scripts/create-admin.js
deploy/              nginx site, hardened systemd unit, backup script
```
