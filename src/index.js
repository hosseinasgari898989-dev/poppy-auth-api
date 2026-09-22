// ==================================================
// Poppy Auth API  |  src/index.js
// Cloudflare Workers + D1 (binding: users_db)
// @simplewebauthn/server  (works with v10 AND v11+)
// Features: passkey login, stored-credential hints,
// recovery codes, add-new-device
// ==================================================

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

// ==================================================
// 1) CONFIG
// ==================================================
const RP_NAME = 'Poppy Playtime Archive';
const WEBAUTHN_TIMEOUT = 120000;
const CHALLENGE_TTL = '+10 minutes';
const SESSION_TTL = '+30 days';
const MAX_CREDENTIAL_HINTS = 20;

// Only these origins may register / login (no trailing slash).
const ALLOWED_ORIGINS = [
  'https://playtimechannelhv.github.io',
  'https://hosseinasgari898989-dev.github.io',
];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Token',
};

// User-facing messages (Persian, simple)
const MSG = {
  generic: 'مشکلی پیش آمد. دوباره تلاش کن.',
  server: 'مشکلی در سرور پیش آمد. کمی بعد دوباره تلاش کن.',
  origin: 'این سایت اجازه‌ی استفاده از ورود با اثر انگشت را ندارد.',
  fields: 'اطلاعات ارسالی ناقص است. صفحه را دوباره باز کن و امتحان کن.',
  challenge: 'زمان تأیید تمام شد. دوباره تلاش کن.',
  verify: 'تأیید اثر انگشت انجام نشد. دوباره تلاش کن.',
  dup: 'این اثر انگشت قبلاً ثبت شده است.',
  credNotFound:
    'این اثر انگشت در سایت ثبت نشده است. اگر قبلاً ثبت‌نام کرده‌ای با کد بازیابی وارد شو، وگرنه ثبت‌نام جدید بزن.',
  noUser: 'حساب پیدا نشد.',
  disabled: 'این حساب غیرفعال شده است.',
  notLoggedIn: 'وارد نشده‌ای یا مدت نشست تمام شده. دوباره وارد شو.',
  badRecovery: 'کد بازیابی درست نیست. با دقت دوباره وارد کن.',
  registrationClosed: 'ثبت‌نام حساب جدید بسته است. با حساب موجود وارد شو و از گزینه افزودن دستگاه استفاده کن.',
  googleNotConfigured: 'ورود با Google هنوز در سرور تنظیم نشده است.',
  googleInvalid: 'حساب Google قابل تأیید نبود. دوباره انتخابش کن.',
  googleAccountExists: 'این حساب Google قبلاً یک حساب Poppy دارد. با همان حساب وارد شو و دستگاه جدید را اضافه کن.',
  googleAlreadyLinked: 'این حساب Poppy از قبل به یک Google Account وصل است.',
  rateLimited: 'تعداد تلاش‌ها زیاد است. چند دقیقه بعد دوباره امتحان کن.',
  notFound: 'آدرس پیدا نشد.',
};

// ==================================================
// 2) HELPERS
// ==================================================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// error code stays in "error" (old clients), Persian text in "message"
function fail(code, status = 400, message = '', extra = {}) {
  return json({ success: false, error: code, message: message || MSG.generic, ...extra }, status);
}

function getOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin || origin === 'null') return null;
  return ALLOWED_ORIGINS.includes(origin) ? origin : null;
}

async function ensureGoogleIdentityTables(env) {
  await env.users_db.prepare('CREATE TABLE IF NOT EXISTS google_identities (user_id INTEGER PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE, google_email TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
  await env.users_db.prepare('CREATE TABLE IF NOT EXISTS google_registration_challenges (challenge_id TEXT PRIMARY KEY, google_sub TEXT NOT NULL, google_email TEXT, google_name TEXT, expires_at TEXT NOT NULL)').run();
}

async function verifyGoogleIdToken(idToken, env) {
  const clientId = String(env.GOOGLE_CLIENT_ID || '').trim();
  if (!clientId) return { error: 'google_not_configured' };
  if (!idToken || typeof idToken !== 'string' || idToken.length < 100) return { error: 'invalid_google_credential' };
  try {
    const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
    if (!r.ok) return { error: 'invalid_google_credential' };
    const p = await r.json();
    const iss = String(p.iss || '');
    const aud = String(p.aud || '');
    const sub = String(p.sub || '');
    const email = String(p.email || '');
    const verified = p.email_verified === true || String(p.email_verified).toLowerCase() === 'true';
    const exp = Number(p.exp || 0);
    if (!sub || !email || !verified || aud !== clientId || (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') || !exp || exp <= Math.floor(Date.now() / 1000)) return { error: 'invalid_google_credential' };
    return { ok: true, sub, email, name: String(p.name || '') };
  } catch (e) {
    console.error('google_token_verify_failed', e);
    return { error: 'invalid_google_credential' };
  }
}

async function saveGoogleRegistrationChallenge(env, data) {
  await ensureGoogleIdentityTables(env);
  await env.users_db.prepare("INSERT INTO google_registration_challenges (challenge_id, google_sub, google_email, google_name, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))").bind(data.challengeId, data.googleSub, data.googleEmail, data.googleName || '').run();
}

async function takeGoogleRegistrationChallenge(env, challengeId) {
  await ensureGoogleIdentityTables(env);
  const row = await env.users_db.prepare("SELECT * FROM google_registration_challenges WHERE challenge_id = ? AND expires_at > datetime('now')").bind(challengeId).first();
  if (row) await env.users_db.prepare('DELETE FROM google_registration_challenges WHERE challenge_id = ?').bind(challengeId).run();
  return row;
}

function b64uEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64uDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

// accepts string (already base64url) or bytes
function toB64u(x) {
  return typeof x === 'string' ? x : b64uEncode(x);
}

function randomId(bytes = 16) {
  return b64uEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

function generateDisplayId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rnd = crypto.getRandomValues(new Uint8Array(4));
  let id = '';
  for (let i = 0; i < 4; i++) id += chars[rnd[i] % chars.length];
  return '#' + id;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    return null;
  }
}

function getToken(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.replace(/^Bearer\s+/i, '').trim();
}

async function ensureRateLimitTable(env) {
  await env.users_db.prepare(
    `CREATE TABLE IF NOT EXISTS auth_rate_limits (
      key TEXT PRIMARY KEY,
      window_start INTEGER NOT NULL,
      count INTEGER NOT NULL
    )`
  ).run();
}

function clientKey(request, scope) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  return scope + ':' + ip;
}

async function takeRateLimit(env, key, limit, windowMs) {
  await ensureRateLimitTable(env);
  const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
  const row = await env.users_db
    .prepare('SELECT window_start, count FROM auth_rate_limits WHERE key = ?')
    .bind(key)
    .first();

  if (!row || Number(row.window_start) !== windowStart) {
    await env.users_db.prepare(
      `INSERT INTO auth_rate_limits (key, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = 1`
    ).bind(key, windowStart).run();
    return { allowed: true, retryAfter: Math.ceil((windowStart + windowMs - Date.now()) / 1000) };
  }

  if (Number(row.count) >= limit) {
    return { allowed: false, retryAfter: Math.max(1, Math.ceil((windowStart + windowMs - Date.now()) / 1000)) };
  }

  await env.users_db
    .prepare('UPDATE auth_rate_limits SET count = count + 1 WHERE key = ? AND window_start = ?')
    .bind(key, windowStart).run();

  return { allowed: true, retryAfter: Math.ceil((windowStart + windowMs - Date.now()) / 1000) };
}

async function guardRateLimit(request, env, scope, limit, windowMs) {
  try {
    const r = await takeRateLimit(env, clientKey(request, scope), limit, windowMs);
    if (!r.allowed) {
      return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: r.retryAfter });
    }
    return null;
  } catch (e) {
    console.error('rate_limit_error', scope, e);
    return fail('rate_limit_unavailable', 503, MSG.server);
  }
}

// ---------- recovery code helpers ----------
// 25 chars from a 32-char alphabet (125 bits), shown as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
function generateRecoveryCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rnd = crypto.getRandomValues(new Uint8Array(25));
  let raw = '';
  for (let i = 0; i < 25; i++) raw += chars[rnd[i] % 32];
  return raw.match(/.{5}/g).join('-');
}

function normalizeRecoveryCode(input) {
  return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

// ==================================================
// 3) DB HELPERS
// ==================================================
async function cleanup(env) {
  await env.users_db.batch([
    env.users_db.prepare("DELETE FROM challenges WHERE expires_at < datetime('now')"),
    env.users_db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')"),
    env.users_db.prepare("DELETE FROM google_registration_challenges WHERE expires_at < datetime('now')"),
  ]);
}

async function saveChallenge(env, { id, userId, challenge, type, origin, rpId }) {
  await env.users_db
    .prepare(
      "INSERT INTO challenges (id, user_id, challenge, type, origin, rp_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now', ?))"
    )
    .bind(id, userId, challenge, type, origin, rpId, CHALLENGE_TTL)
    .run();
}

// single-use: fetch valid challenge then delete it
async function takeChallenge(env, id, type) {
  const ch = await env.users_db
    .prepare("SELECT * FROM challenges WHERE id = ? AND type = ? AND expires_at > datetime('now')")
    .bind(id, type)
    .first();
  if (ch) {
    await env.users_db.prepare('DELETE FROM challenges WHERE id = ?').bind(id).run();
  }
  return ch;
}

async function createSession(env, userId, request) {
  const token = randomId(32);
  await env.users_db
    .prepare("INSERT INTO sessions (token, user_id, expires_at, user_agent) VALUES (?, ?, datetime('now', ?), ?)")
    .bind(token, userId, SESSION_TTL, request.headers.get('User-Agent') || '')
    .run();
  return token;
}

// returns { user } or { error: Response }
async function getSessionUser(request, env) {
  const token = getToken(request);
  if (!token) return { error: fail('no_token', 401, MSG.notLoggedIn) };

  const row = await env.users_db
    .prepare(
      "SELECT s.user_id AS user_id, u.display_id AS display_id, u.status AS status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > datetime('now')"
    )
    .bind(token)
    .first();
  if (!row) return { error: fail('invalid_token', 401, MSG.notLoggedIn) };
  if (row.status !== 'active') return { error: fail('account_disabled', 403, MSG.disabled) };

  return { user: { id: row.user_id, displayId: row.display_id, status: row.status } };
}

// issue (or replace) the recovery code of a user. returns code or null
async function issueRecoveryCode(env, userId) {
  try {
    const code = generateRecoveryCode();
    const hash = await sha256Hex(normalizeRecoveryCode(code));
    await env.users_db
      .prepare(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, created_at = CURRENT_TIMESTAMP'
      )
      .bind(userId, hash)
      .run();
    return code;
  } catch (e) {
    console.error('recovery_issue_failed', e);
    return null;
  }
}

// keep only hinted credential ids that really exist
async function findKnownCredentialIds(env, ids) {
  if (!Array.isArray(ids)) return [];
  const clean = [
    ...new Set(ids.filter((x) => typeof x === 'string' && /^[A-Za-z0-9_-]{16,1024}$/.test(x))),
  ].slice(0, MAX_CREDENTIAL_HINTS);
  if (!clean.length) return [];

  const marks = clean.map(() => '?').join(',');
  const res = await env.users_db
    .prepare(`SELECT credential_id FROM credentials WHERE credential_id IN (${marks})`)
    .bind(...clean)
    .all();
  return (res.results || []).map((r) => r.credential_id);
}

// works with both library layouts
//  v11+ : info.credential = { id, publicKey, counter }
//  v10  : info.credentialID, info.credentialPublicKey, info.counter
function extractRegistration(verification) {
  const info = verification && verification.registrationInfo;
  if (!info) return null;
  const rawId = info.credential ? info.credential.id : info.credentialID;
  const rawKey = info.credential ? info.credential.publicKey : info.credentialPublicKey;
  const counter = (info.credential ? info.credential.counter : info.counter) || 0;
  if (!rawId || !rawKey) return null;
  return { credentialIdB64: toB64u(rawId), publicKeyB64: toB64u(rawKey), counter };
}

// ==================================================
 // 3.5) OWNER ADMIN HELPERS
 // ==================================================
 function isOwnerAdmin(request, env) {
   const configured = env.AUTH_ADMIN_TOKEN || '';
   const token = request.headers.get('X-Admin-Token') || '';
   return !!configured && token === configured;
 }

 function adminUnauthorized() {
   return fail('unauthorized', 401, 'دسترسی مدیریت نیاز به کلید معتبر دارد.');
 }

 function parseUserId(path) {
   const m = path.match(/^\/api\/admin\/users\/([^/]+)/);
   return m ? decodeURIComponent(m[1]) : null;
 }

 async function adminListUsers(request, env) {
   const url = new URL(request.url);
   const limitParam = Number.parseInt(url.searchParams.get('limit') || '200', 10);
   const limit = Math.min(Math.max(Number.isFinite(limitParam) ? limitParam : 200, 1), 500);
   const search = (url.searchParams.get('search') || '').trim();

   let query = `
     SELECT
       u.id,
       u.display_id,
       u.status,
       u.trust_level,
       u.last_login,
       u.created_at,
       (SELECT COUNT(*) FROM credentials c WHERE c.user_id = u.id) AS credential_count,
       (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > datetime('now')) AS active_session_count,
       EXISTS(SELECT 1 FROM recovery_codes r WHERE r.user_id = u.id) AS has_recovery
     FROM users u
   `;
   const binds = [];
   if (search) {
     query += ' WHERE u.display_id LIKE ? OR CAST(u.id AS TEXT) LIKE ?';
     binds.push('%' + search + '%', '%' + search + '%');
   }
   query += ' ORDER BY u.id ASC LIMIT ?';
   binds.push(limit);

   const { results } = await env.users_db.prepare(query).bind(...binds).all();
   const users = (results || []).map((r) => ({
     id: r.id,
     displayId: r.display_id,
     status: r.status,
     trustLevel: r.trust_level,
     lastLogin: r.last_login || null,
     createdAt: r.created_at || null,
     credentialCount: Number(r.credential_count || 0),
     activeSessionCount: Number(r.active_session_count || 0),
     hasRecovery: !!r.has_recovery,
   }));
   return json({ success: true, users });
 }

 async function adminUserDetail(request, env, userId) {
   const user = await env.users_db
     .prepare('SELECT id, display_id, status, trust_level, last_login, created_at FROM users WHERE id = ?')
     .bind(userId)
     .first();
   if (!user) return fail('user_not_found', 404, MSG.noUser);

   const creds = await env.users_db
     .prepare('SELECT credential_id, counter, device_info, last_used FROM credentials WHERE user_id = ? ORDER BY credential_id ASC')
     .bind(userId)
     .all();

   const sessions = await env.users_db
     .prepare("SELECT token, expires_at, user_agent FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY expires_at DESC")
     .bind(userId)
     .all();

   return json({
     success: true,
     user: {
       id: user.id,
       displayId: user.display_id,
       status: user.status,
       trustLevel: user.trust_level,
       lastLogin: user.last_login || null,
       createdAt: user.created_at || null,
       credentialCount: (creds.results || []).length,
       activeSessionCount: (sessions.results || []).length,
       credentials: (creds.results || []).map((r) => ({
         credentialId: r.credential_id,
         counter: r.counter || 0,
         deviceInfo: r.device_info || '',
         lastUsed: r.last_used || null,
       })),
       sessions: (sessions.results || []).map((r) => ({
         expiresAt: r.expires_at || null,
         userAgent: r.user_agent || '',
       })),
     },
   });
 }

 async function adminSetUserStatus(env, userId, status) {
   if (!['active', 'disabled'].includes(status)) {
     return fail('invalid_status', 400, 'وضعیت حساب نامعتبر است.');
   }
   const exists = await env.users_db.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
   if (!exists) return fail('user_not_found', 404, MSG.noUser);

   await env.users_db.prepare('UPDATE users SET status = ? WHERE id = ?').bind(status, userId).run();
   if (status === 'disabled') {
     await env.users_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
   }
   return json({ success: true, status });
 }

 async function adminRevokeSessions(env, userId) {
   const exists = await env.users_db.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
   if (!exists) return fail('user_not_found', 404, MSG.noUser);
   const result = await env.users_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
   return json({ success: true, count: Number((result.meta && result.meta.changes) || 0) });
 }

 async function adminRemoveCredential(env, userId, credentialId) {
   const user = await env.users_db.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
   if (!user) return fail('user_not_found', 404, MSG.noUser);

   const countRow = await env.users_db
     .prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?')
     .bind(userId)
     .first();
   const count = Number((countRow && countRow.n) || 0);
   if (count <= 1) {
     return fail('last_credential', 400, 'برای امنیت، آخرین Passkey حذف نمی‌شود.');
   }

   const result = await env.users_db
     .prepare('DELETE FROM credentials WHERE user_id = ? AND credential_id = ?')
     .bind(userId, credentialId)
     .run();

   if (!result.meta || Number(result.meta.changes || 0) !== 1) {
     return fail('credential_not_found', 404, 'Passkey پیدا نشد.');
   }
   return json({ success: true });
 }

 async function adminRegenerateRecovery(env, userId) {
   const user = await env.users_db.prepare('SELECT id, status FROM users WHERE id = ?').bind(userId).first();
   if (!user) return fail('user_not_found', 404, MSG.noUser);
   if (user.status !== 'active') return fail('account_disabled', 403, MSG.disabled);
   const recoveryCode = await issueRecoveryCode(env, userId);
   if (!recoveryCode) return fail('recovery_unavailable', 503, MSG.server);
   return json({ success: true, recoveryCode });
 }
 
 // ==================================================
// 4) ROUTER
// ==================================================
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const path = new URL(request.url).pathname;
    const method = request.method;

    try {
      if (path === '/' && method === 'GET') {
        return json({ ok: true, service: 'poppy-auth-api', time: new Date().toISOString() });
      }

      // ----- existing endpoints -----
      if (path === '/api/auth/google/config' && method === 'GET') {
        const clientId = String(env.GOOGLE_CLIENT_ID || '').trim();
        if (!clientId) return fail('google_not_configured', 503, MSG.googleNotConfigured);
        return json({ success: true, clientId });
      }
      if (path === '/api/auth/google/link' && method === 'POST') return await linkGoogle(request, env);
      if (path === '/api/auth/register/begin' && method === 'POST') {
        ctx.waitUntil(cleanup(env).catch(() => {}));
        return await registerBegin(request, env);
      }
      if (path === '/api/auth/register/finish' && method === 'POST') return await registerFinish(request, env);

      if (path === '/api/auth/login/begin' && method === 'POST') {
        ctx.waitUntil(cleanup(env).catch(() => {}));
        return await loginBegin(request, env);
      }
      if (path === '/api/auth/login/finish' && method === 'POST') return await loginFinish(request, env);

      if (path === '/api/auth/me' && method === 'GET') return await me(request, env);
      if (path === '/api/auth/logout' && method === 'POST') return await logout(request, env);

      // ----- owner admin endpoints -----
      if (path.startsWith('/api/admin/')) {
        if (!isOwnerAdmin(request, env)) return adminUnauthorized();

        if (path === '/api/admin/login' && method === 'POST') {
          return json({ success: true });
        }
        if (path === '/api/admin/users' && method === 'GET') {
          return await adminListUsers(request, env);
        }

        const userId = parseUserId(path);
        if (!userId) return fail('not_found', 404, MSG.notFound);

        if (path === `/api/admin/users/${encodeURIComponent(userId)}` && method === 'GET') {
          return await adminUserDetail(request, env, userId);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/status` && method === 'POST') {
          const body = await readJson(request);
          return await adminSetUserStatus(env, userId, body && body.status);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/revoke-sessions` && method === 'POST') {
          return await adminRevokeSessions(env, userId);
        }
        if (path.startsWith(`/api/admin/users/${encodeURIComponent(userId)}/credentials/`) && method === 'DELETE') {
          const credentialId = decodeURIComponent(path.split('/').pop() || '');
          return await adminRemoveCredential(env, userId, credentialId);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/recovery/regenerate` && method === 'POST') {
          return await adminRegenerateRecovery(env, userId);
        }

        return fail('not_found', 404, MSG.notFound);
      }

      // ----- new endpoints -----
      if (path === '/api/auth/recovery/login' && method === 'POST') return await recoveryLogin(request, env);
      if (path === '/api/auth/recovery/regenerate' && method === 'POST') return await recoveryRegenerate(request, env);
      if (path === '/api/auth/credential/add/begin' && method === 'POST') return await addCredentialBegin(request, env);
      if (path === '/api/auth/credential/add/finish' && method === 'POST') return await addCredentialFinish(request, env);

      return fail('not_found', 404, MSG.notFound);
    } catch (e) {
      console.error(e);
      return fail('server_error', 500, MSG.server, { detail: String((e && e.message) || e) });
    }
  },
};

// ==================================================
// 5) REGISTER
// ==================================================

async function registerBegin(request, env) {
  const origin = getOrigin(request);
  if (!origin) return fail('origin_not_allowed', 403, MSG.origin);
  const body = await readJson(request);
  const google = await verifyGoogleIdToken(body && body.googleIdToken, env);
  if (google.error) return fail(google.error, google.error === 'google_not_configured' ? 503 : 401, google.error === 'google_not_configured' ? MSG.googleNotConfigured : MSG.googleInvalid);
  await ensureGoogleIdentityTables(env);
  const existing = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE google_sub = ?').bind(google.sub).first();
  if (existing) return fail('google_account_exists', 409, MSG.googleAccountExists);
  const rate = await takeRateLimit(env, 'register-google-begin:' + google.sub, 4, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });
  const rpId = new URL(origin).hostname;
  const userHandle = crypto.getRandomValues(new Uint8Array(16));
  const userHandleB64 = b64uEncode(userHandle);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userID: userHandle,
    userName: 'poppy-' + userHandleB64.slice(0, 6),
    userDisplayName: google.name || google.email,
    attestationType: 'none',
    timeout: WEBAUTHN_TIMEOUT,
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    supportedAlgorithmIDs: [-7, -257],
  });
  const challengeId = randomId(16);
  await saveChallenge(env, { id: challengeId, userId: userHandleB64, challenge: options.challenge, type: 'register', origin, rpId });
  await saveGoogleRegistrationChallenge(env, { challengeId, googleSub: google.sub, googleEmail: google.email, googleName: google.name });
  return json({ success: true, options, challengeId });
}

async function registerFinish(request, env) {
  const body = await readJson(request);
  const { challengeId, credential } = body || {};
  if (!challengeId || !credential) return fail('missing_fields', 400, MSG.fields);
  const ch = await takeChallenge(env, challengeId, 'register');
  if (!ch) return fail('challenge_not_found_or_expired', 400, MSG.challenge);
  const googleCh = await takeGoogleRegistrationChallenge(env, challengeId);
  if (!googleCh) return fail('invalid_google_credential', 401, MSG.googleInvalid);
  const rate = await takeRateLimit(env, 'register-google-finish:' + googleCh.google_sub, 6, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });
  const existing = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE google_sub = ?').bind(googleCh.google_sub).first();
  if (existing) return fail('google_account_exists', 409, MSG.googleAccountExists);
  let verification;
  try {
    verification = await verifyRegistrationResponse({ response: credential, expectedChallenge: ch.challenge, expectedOrigin: ch.origin, expectedRPID: ch.rp_id, requireUserVerification: true });
  } catch (e) {
    return fail('verification_failed: ' + e.message, 400, MSG.verify, { detail: e.message });
  }
  if (!verification.verified) return fail('not_verified', 400, MSG.verify);
  const reg = extractRegistration(verification);
  if (!reg) return fail('bad_registration_info', 500, MSG.server);
  const dup = await env.users_db.prepare('SELECT credential_id FROM credentials WHERE credential_id = ?').bind(reg.credentialIdB64).first();
  if (dup) return fail('credential_already_registered', 409, MSG.dup);
  let displayId = null;
  for (let i = 0; i < 10; i++) {
    const id = generateDisplayId();
    const exists = await env.users_db.prepare('SELECT id FROM users WHERE display_id = ?').bind(id).first();
    if (!exists) { displayId = id; break; }
  }
  if (!displayId) return fail('id_generation_failed', 500, MSG.server);
  const userAgent = request.headers.get('User-Agent') || '';
  await env.users_db.batch([
    env.users_db.prepare('INSERT INTO users (display_id, status, trust_level) VALUES (?, ?, ?)').bind(displayId, 'active', 'new'),
    env.users_db.prepare('INSERT INTO credentials (credential_id, user_id, public_key, counter, device_info) VALUES (?, (SELECT id FROM users WHERE display_id = ?), ?, ?, ?)').bind(reg.credentialIdB64, displayId, reg.publicKeyB64, reg.counter, userAgent),
    env.users_db.prepare('INSERT INTO google_identities (user_id, google_sub, google_email) VALUES ((SELECT id FROM users WHERE display_id = ?), ?, ?)').bind(displayId, googleCh.google_sub, googleCh.google_email)
  ]);
  const user = await env.users_db.prepare('SELECT id, display_id FROM users WHERE display_id = ?').bind(displayId).first();
  if (!user) return fail('user_create_failed', 500, MSG.server);
  const token = await createSession(env, user.id, request);
  const recoveryCode = await issueRecoveryCode(env, user.id);
  return json({ success: true, token, user: { id: user.id, displayId: user.display_id }, recoveryCode });
}

// ==================================================
// 6) LOGIN
// ==================================================
async function loginBegin(request, env) {
  const rate = await guardRateLimit(request, env, 'login-begin', 12, 10 * 60 * 1000);
  if (rate) return rate;

  const origin = getOrigin(request);
  if (!origin) return fail('origin_not_allowed', 403, MSG.origin);
  const rpId = new URL(origin).hostname;

  // optional body: { credentialIds: [...] } remembered by the device
  const body = await readJson(request);
  const hinted = await findKnownCredentialIds(env, body && body.credentialIds);

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    userVerification: 'required',
    timeout: WEBAUTHN_TIMEOUT,
  });

  // known ids -> explicit list (works on phones that reject an empty list)
  // no ids     -> empty list (discoverable passkey)
  if (hinted.length) {
    options.allowCredentials = hinted.map((id) => ({ id, type: 'public-key' }));
  }

  const challengeId = randomId(16);
  await saveChallenge(env, {
    id: challengeId,
    userId: '',
    challenge: options.challenge,
    type: 'login',
    origin,
    rpId,
  });

  return json({ success: true, options, challengeId });
}

async function loginFinish(request, env) {
  const rate = await guardRateLimit(request, env, 'login-finish', 12, 60 * 1000);
  if (rate) return rate;

  const body = await readJson(request);
  const { challengeId, credential } = body || {};
  if (!challengeId || !credential || !credential.id) return fail('missing_fields', 400, MSG.fields);

  const ch = await takeChallenge(env, challengeId, 'login');
  if (!ch) return fail('challenge_not_found_or_expired', 400, MSG.challenge);

  const storedCred = await env.users_db
    .prepare('SELECT * FROM credentials WHERE credential_id = ?')
    .bind(credential.id)
    .first();
  if (!storedCred) return fail('credential_not_found', 400, MSG.credNotFound);

  const publicKeyBytes = b64uDecode(storedCred.public_key);
  const storedCounter = storedCred.counter || 0;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: ch.origin,
      expectedRPID: ch.rp_id,
      // v11+ reads "credential"
      credential: {
        id: storedCred.credential_id,
        publicKey: publicKeyBytes,
        counter: storedCounter,
      },
      // v10 reads "authenticator"
      authenticator: {
        credentialID: b64uDecode(storedCred.credential_id),
        credentialPublicKey: publicKeyBytes,
        counter: storedCounter,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    return fail('verification_failed: ' + e.message, 400, MSG.verify, { detail: e.message });
  }
  if (!verification.verified) return fail('not_verified', 400, MSG.verify);

  const user = await env.users_db
    .prepare('SELECT * FROM users WHERE id = ?')
    .bind(storedCred.user_id)
    .first();
  if (!user) return fail('user_not_found', 400, MSG.noUser);
  if (user.status !== 'active') return fail('account_disabled', 403, MSG.disabled);

  await env.users_db.batch([
    env.users_db
      .prepare('UPDATE credentials SET counter = ?, last_used = CURRENT_TIMESTAMP WHERE credential_id = ?')
      .bind(verification.authenticationInfo.newCounter || 0, storedCred.credential_id),
    env.users_db
      .prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
      .bind(user.id),
  ]);

  const token = await createSession(env, user.id, request);

  return json({ success: true, token, user: { id: user.id, displayId: user.display_id } });
}

async function linkGoogle(request, env) {
  const session = await getSessionUser(request, env);
  if (session.error) return session.error;
  const body = await readJson(request);
  const google = await verifyGoogleIdToken(body && body.googleIdToken, env);
  if (google.error) return fail(google.error, google.error === 'google_not_configured' ? 503 : 401, google.error === 'google_not_configured' ? MSG.googleNotConfigured : MSG.googleInvalid);
  await ensureGoogleIdentityTables(env);
  const existingForUser = await env.users_db.prepare('SELECT google_sub FROM google_identities WHERE user_id = ?').bind(session.user.id).first();
  if (existingForUser && existingForUser.google_sub === google.sub) return json({ success: true, linked: true, alreadyLinked: true });
  if (existingForUser) return fail('google_already_linked', 409, MSG.googleAlreadyLinked);
  const existing = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE google_sub = ?').bind(google.sub).first();
  if (existing && String(existing.user_id) !== String(session.user.id)) return fail('google_account_exists', 409, MSG.googleAccountExists);
  await env.users_db.prepare('INSERT INTO google_identities (user_id, google_sub, google_email) VALUES (?, ?, ?)').bind(session.user.id, google.sub, google.email).run();
  return json({ success: true, linked: true, email: google.email });
}

// ==================================================
// 7) SESSION (me / logout)
// ==================================================
async function me(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const c = await env.users_db
    .prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?')
    .bind(s.user.id)
    .first();

  let googleLinked = false;
  try {
    await ensureGoogleIdentityTables(env);
    const g = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE user_id = ?').bind(s.user.id).first();
    googleLinked = !!g;
  } catch (e) {
    googleLinked = false;
  }

  let hasRecovery = false;
  try {
    const r = await env.users_db
      .prepare('SELECT user_id FROM recovery_codes WHERE user_id = ?')
      .bind(s.user.id)
      .first();
    hasRecovery = !!r;
  } catch (e) {
    hasRecovery = false;
  }

  return json({
    success: true,
    user: {
      id: s.user.id,
      displayId: s.user.displayId,
      status: s.user.status,
      credentialCount: (c && c.n) || 0,
      hasRecovery,
      googleLinked,
    },
  });
}

async function logout(request, env) {
  const token = getToken(request);
  if (token) {
    await env.users_db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return json({ success: true });
}

// ==================================================
// 8) RECOVERY CODE (new)
// ==================================================
// login with recovery code; the used code is replaced by a new one
async function recoveryLogin(request, env) {
  const rate = await guardRateLimit(request, env, 'recovery-login', 5, 15 * 60 * 1000);
  if (rate) return rate;

  const body = await readJson(request);
  const norm = normalizeRecoveryCode(body && body.code);
  if (norm.length !== 25) return fail('invalid_recovery_code', 400, MSG.badRecovery);

  const hash = await sha256Hex(norm);
  let row = null;
  try {
    row = await env.users_db
      .prepare('SELECT user_id FROM recovery_codes WHERE code_hash = ?')
      .bind(hash)
      .first();
  } catch (e) {
    console.error('recovery_lookup_failed', e);
    return fail('recovery_unavailable', 500, MSG.server);
  }
  if (!row) return fail('invalid_recovery_code', 401, MSG.badRecovery);

  const user = await env.users_db
    .prepare('SELECT * FROM users WHERE id = ?')
    .bind(row.user_id)
    .first();
  if (!user) return fail('user_not_found', 400, MSG.noUser);
  if (user.status !== 'active') return fail('account_disabled', 403, MSG.disabled);

  const newCode = await issueRecoveryCode(env, user.id);
  await env.users_db
    .prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
    .bind(user.id)
    .run();
  const token = await createSession(env, user.id, request);

  return json({
    success: true,
    token,
    user: { id: user.id, displayId: user.display_id },
    recoveryCode: newCode,
  });
}

// logged-in user makes a fresh code (old one stops working)
async function recoveryRegenerate(request, env) {
  const rate = await guardRateLimit(request, env, 'recovery-regenerate', 3, 60 * 60 * 1000);
  if (rate) return rate;

  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const code = await issueRecoveryCode(env, s.user.id);
  if (!code) return fail('recovery_unavailable', 500, MSG.server);

  return json({ success: true, recoveryCode: code });
}

// ==================================================
// 9) ADD NEW DEVICE / PASSKEY (new, needs Bearer token)
// ==================================================
async function addCredentialBegin(request, env) {
  const rate = await guardRateLimit(request, env, 'credential-add-begin', 5, 15 * 60 * 1000);
  if (rate) return rate;

  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const origin = getOrigin(request);
  if (!origin) return fail('origin_not_allowed', 403, MSG.origin);
  const rpId = new URL(origin).hostname;

  const existing = await env.users_db
    .prepare('SELECT credential_id FROM credentials WHERE user_id = ?')
    .bind(s.user.id)
    .all();

  const userHandle = crypto.getRandomValues(new Uint8Array(16));

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userID: userHandle,
    userName: s.user.displayId,
    userDisplayName: s.user.displayId,
    attestationType: 'none',
    timeout: WEBAUTHN_TIMEOUT,
    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // do not register the same authenticator twice
  options.excludeCredentials = (existing.results || []).map((r) => ({
    id: r.credential_id,
    type: 'public-key',
  }));

  const challengeId = randomId(16);
  await saveChallenge(env, {
    id: challengeId,
    userId: String(s.user.id),
    challenge: options.challenge,
    type: 'add',
    origin,
    rpId,
  });

  return json({ success: true, options, challengeId });
}

async function addCredentialFinish(request, env) {
  const rate = await guardRateLimit(request, env, 'credential-add-finish', 8, 15 * 60 * 1000);
  if (rate) return rate;

  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const body = await readJson(request);
  const { challengeId, credential } = body || {};
  if (!challengeId || !credential) return fail('missing_fields', 400, MSG.fields);

  const ch = await takeChallenge(env, challengeId, 'add');
  if (!ch || ch.user_id !== String(s.user.id)) {
    return fail('challenge_not_found_or_expired', 400, MSG.challenge);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: ch.origin,
      expectedRPID: ch.rp_id,
      requireUserVerification: true,
    });
  } catch (e) {
    return fail('verification_failed: ' + e.message, 400, MSG.verify, { detail: e.message });
  }
  if (!verification.verified) return fail('not_verified', 400, MSG.verify);

  const reg = extractRegistration(verification);
  if (!reg) return fail('bad_registration_info', 500, MSG.server);

  const dup = await env.users_db
    .prepare('SELECT credential_id FROM credentials WHERE credential_id = ?')
    .bind(reg.credentialIdB64)
    .first();
  if (dup) return fail('credential_already_registered', 409, MSG.dup);

  await env.users_db
    .prepare('INSERT INTO credentials (credential_id, user_id, public_key, counter, device_info) VALUES (?, ?, ?, ?, ?)')
    .bind(reg.credentialIdB64, s.user.id, reg.publicKeyB64, reg.counter, request.headers.get('User-Agent') || '')
    .run();

  const c = await env.users_db
    .prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?')
    .bind(s.user.id)
    .first();

  return json({ success: true, credentialCount: (c && c.n) || 0 });
}
