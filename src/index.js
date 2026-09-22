// ==================================================
// Poppy Auth API  |  src/index.js
// Cloudflare Workers + D1 (binding: users_db)
// Features: Google authentication, password-protected recovery codes,
// sessions, and account settings
// ==================================================

// ==================================================
// 1) CONFIG
// ==================================================
const SESSION_TTL = '+30 days';
const USER_SETTING_KEY_MAX = 64;
const USER_SETTING_VALUE_MAX = 4096;
const USER_SETTING_COUNT_MAX = 64;
const GOOGLE_CLIENT_ID = '246560188376-prs0mf954qddb937v04s7krimjul9845.apps.googleusercontent.com';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Token',
};

// User-facing messages (Persian, simple)
const MSG = {
  generic: 'مشکلی پیش آمد. دوباره تلاش کن.',
  server: 'مشکلی در سرور پیش آمد. کمی بعد دوباره تلاش کن.',
  noUser: 'حساب پیدا نشد.',
  disabled: 'این حساب غیرفعال شده است.',
  notLoggedIn: 'وارد نشده‌ای یا مدت نشست تمام شده. دوباره وارد شو.',
  badRecovery: 'کد بازیابی درست نیست. با دقت دوباره وارد کن.',
  passwordRequired: 'رمز حساب را وارد کن.',
  passwordMismatch: 'رمز و تکرار رمز یکسان نیستند.',
  passwordInvalidLength: 'رمز حساب باید بین ۱۰ تا ۱۲۸ کاراکتر باشد.',
  passwordWeak: 'رمز باید حداقل یک حرف بزرگ، یک حرف کوچک، یک عدد و یک نماد داشته باشد.',
  passwordAlreadySet: 'رمز حساب قبلاً تنظیم شده است.',
  passwordInvalid: 'رمز حساب درست نیست.',
  passwordNotSet: 'برای این حساب هنوز رمز عبور تنظیم نشده است.',
  recoveryCodeUnavailable: 'کد بازیابی قابل نمایش نیست. ابتدا امنیت حساب را کامل کن.',
  recoveryViewCooldown: 'کد بازیابی اخیراً نمایش داده شده است. برای نمایش دوباره باید یک روز کامل صبر کنی.',
  settingKeyInvalid: 'نام تنظیم حساب معتبر نیست.',
  settingValueTooLarge: 'مقدار تنظیم حساب بیش از حد بزرگ است.',
  settingLimitReached: 'تعداد تنظیمات ذخیره‌شده برای این حساب به حد مجاز رسیده است.',
  googleNotConfigured: 'ورود با Google هنوز در سرور تنظیم نشده است.',
  googleInvalid: 'حساب Google قابل تأیید نبود. دوباره انتخابش کن.',
  googleAccountExists: 'این Google Account قبلاً به یک حساب Playtime Channel متصل شده است. برای ورود از همان حساب Google استفاده کن.',
  googleAlreadyLinked: 'این حساب Poppy از قبل به یک Google Account وصل است.',
  googleAccountNotLinked: 'این Google Account هنوز به یک حساب Playtime Channel متصل نیست. برای اولین ورود، با کد بازیابی وارد حساب شو و بعد Google را از مرکز حساب متصل کن.',
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

async function ensureUserSettingsTable(env) {
  await env.users_db.prepare(`
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER NOT NULL,
      setting_key TEXT NOT NULL,
      setting_value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, setting_key)
    )
  `).run();
}

async function getUserSettings(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;
  await ensureUserSettingsTable(env);
  const rows = await env.users_db.prepare('SELECT setting_key, setting_value FROM user_settings WHERE user_id = ?').bind(s.user.id).all();
  const settings = {};
  for (const row of (rows.results || [])) settings[row.setting_key] = row.setting_value;
  return json({ success: true, settings });
}

async function saveUserSetting(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const rate = await takeRateLimit(env, 'user-settings:' + s.user.id, 60, 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const body = await readJson(request);
  const key = String(body && body.key || '').trim();
  const value = typeof (body && body.value) === 'string' ? body.value : String(body && body.value == null ? '' : body.value);

  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) return fail('setting_key_invalid', 400, MSG.settingKeyInvalid);
  if (value.length > USER_SETTING_VALUE_MAX) return fail('setting_value_too_large', 413, MSG.settingValueTooLarge);

  await ensureUserSettingsTable(env);
  const exists = await env.users_db.prepare('SELECT 1 FROM user_settings WHERE user_id = ? AND setting_key = ?').bind(s.user.id, key).first();
  if (!exists) {
    const count = await env.users_db.prepare('SELECT COUNT(*) AS n FROM user_settings WHERE user_id = ?').bind(s.user.id).first();
    if (Number((count && count.n) || 0) >= USER_SETTING_COUNT_MAX) return fail('setting_limit_reached', 409, MSG.settingLimitReached);
  }

  await env.users_db.prepare(`
    INSERT INTO user_settings (user_id, setting_key, setting_value)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, setting_key) DO UPDATE SET
      setting_value = excluded.setting_value,
      updated_at = CURRENT_TIMESTAMP
  `).bind(s.user.id, key, value).run();

  return json({ success: true, key, value });
}

async function ensureGoogleIdentityTables(env) {
  await env.users_db.prepare('CREATE TABLE IF NOT EXISTS google_identities (user_id INTEGER PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE, google_email TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
}

async function verifyGoogleIdToken(idToken, env) {
  const clientId = String(env.GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID || '').trim();
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

const PASSWORD_ITERATIONS = 100000; // Cloudflare Workers PBKDF2 limit
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 128;

async function ensureAccountSecurityTables(env) {
  await env.users_db.batch([
    env.users_db.prepare(`CREATE TABLE IF NOT EXISTS account_passwords (
      user_id INTEGER PRIMARY KEY,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      iterations INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.users_db.prepare(`CREATE TABLE IF NOT EXISTS recovery_code_secrets (
      user_id INTEGER PRIMARY KEY,
      iv TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.users_db.prepare(`CREATE TABLE IF NOT EXISTS recovery_codes (
      user_id INTEGER PRIMARY KEY,
      code_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.users_db.prepare(`CREATE TABLE IF NOT EXISTS recovery_code_views (
      user_id INTEGER PRIMARY KEY,
      last_viewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`)
  ]);
}

function validatePasswordInput(password, confirm) {
  const p = typeof password === 'string' ? password : '';
  const c = typeof confirm === 'string' ? confirm : '';
  if (!p || !c) return { error: 'passwordRequired' };
  if (p.length < PASSWORD_MIN_LENGTH || p.length > PASSWORD_MAX_LENGTH) return { error: 'passwordInvalidLength' };
  if (p !== c) return { error: 'passwordMismatch' };
  if (!/[A-Z]/.test(p) || !/[a-z]/.test(p) || !/[0-9]/.test(p) || !/[^A-Za-z0-9]/.test(p)) return { error: 'passwordWeak' };
  return null;
}

function randomSaltB64(bytes = 16) { return b64uEncode(crypto.getRandomValues(new Uint8Array(bytes))); }

async function derivePasswordHash(password, saltB64, iterations = PASSWORD_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64uDecode(saltB64), iterations, hash: 'SHA-256' }, base, 256);
  return b64uEncode(new Uint8Array(bits));
}

async function deriveRecoveryKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64uDecode(saltB64), iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptRecoveryCode(password, saltB64, iterations, code) {
  const key = await deriveRecoveryKey(password, saltB64, iterations);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(code));
  return { iv: b64uEncode(iv), ciphertext: b64uEncode(new Uint8Array(ciphertext)) };
}

async function decryptRecoveryCode(password, saltB64, iterations, ivB64, ciphertextB64) {
  const key = await deriveRecoveryKey(password, saltB64, iterations);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64uDecode(ivB64) }, key, b64uDecode(ciphertextB64));
  return new TextDecoder().decode(plain);
}

async function preparePasswordPackage(password, recoveryCode) {
  const salt = randomSaltB64();
  const iterations = PASSWORD_ITERATIONS;
  const passwordHash = await derivePasswordHash(password, salt, iterations);
  const secret = await encryptRecoveryCode(password, salt, iterations, recoveryCode);
  return { salt, iterations, passwordHash, iv: secret.iv, ciphertext: secret.ciphertext };
}

// ==================================================
// 3) DB HELPERS
// ==================================================
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
    await env.users_db.batch([
      env.users_db.prepare(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, created_at = CURRENT_TIMESTAMP'
      ).bind(userId, hash),
      env.users_db.prepare('DELETE FROM recovery_code_views WHERE user_id = ?').bind(userId)
    ]);
    return code;
  } catch (e) {
    console.error('recovery_issue_failed', e);
    return null;
  }
}

// ==================================================
// 3.5) OWNER / ADMIN ACCESS HELPERS
// ==================================================
const OWNER_ADMIN_KEYWORD_HASH = '3cc6e58c29044816942c6527628b0a3da4f4197d929a64cb59e7b9cea020c2c4';
const OWNER_SESSION_TTL = '+24 hours';
const ADMIN_ROLE_LEVELS = {
  viewer: 1,
  moderator: 2,
  admin: 3,
  owner: 100
};

async function ensureAdminTables(env) {
  await env.users_db.batch([
    env.users_db.prepare(`
      CREATE TABLE IF NOT EXISTS admin_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        role_level INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'active',
        is_builtin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_login_at TEXT,
        login_count INTEGER NOT NULL DEFAULT 0
      )
    `),
    env.users_db.prepare(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY,
        admin_account_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
    env.users_db.prepare(`
      CREATE TABLE IF NOT EXISTS admin_login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_account_id INTEGER NOT NULL,
        logged_in_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        user_agent TEXT
      )
    `)
  ]);

  const masterToken = String(env.AUTH_ADMIN_TOKEN || '').trim();
  if (masterToken) {
    const hash = await sha256Hex(masterToken);
    const existing = await env.users_db.prepare(
      'SELECT id FROM admin_accounts WHERE is_builtin = 1 LIMIT 1'
    ).first();

    if (existing) {
      await env.users_db.prepare(`
        UPDATE admin_accounts
        SET label = 'مالک اصلی',
            token_hash = ?,
            role_level = 100,
            status = 'active',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(hash, existing.id).run();
    } else {
      await env.users_db.prepare(`
        INSERT INTO admin_accounts
          (label, token_hash, role_level, status, is_builtin)
        VALUES ('مالک اصلی', ?, 100, 'active', 1)
      `).bind(hash).run();
    }
  }
}

function adminUnauthorized() {
  return fail('unauthorized', 401, 'دسترسی مدیریت نیاز به کلید معتبر دارد.');
}

function adminForbidden() {
  return fail('forbidden', 403, 'سطح دسترسی لازم برای این عملیات را نداری.');
}

function parseUserId(path) {
  const m = path.match(/^\/api\/admin\/users\/([^/]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function parseAdminAccountId(path) {
  const m = path.match(/^\/api\/admin\/administrators\/(\\d+)/);
  return m ? Number.parseInt(m[1], 10) : null;
}

async function getAdminIdentity(request, env) {
  const token = request.headers.get('X-Admin-Token') || '';
  if (!token) return null;

  await ensureAdminTables(env);
  const hash = await sha256Hex(token);

  const session = await env.users_db.prepare(`
    SELECT s.admin_account_id, a.label, a.role_level, a.status, a.is_builtin
    FROM admin_sessions s
    JOIN admin_accounts a ON a.id = s.admin_account_id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now')
    LIMIT 1
  `).bind(hash).first();

  if (session && session.status === 'active') {
    return {
      id: Number(session.admin_account_id),
      label: session.label,
      roleLevel: Number(session.role_level || 1),
      owner: true,
      session: true
    };
  }

  const account = await env.users_db.prepare(`
    SELECT id, label, role_level, status, is_builtin
    FROM admin_accounts
    WHERE token_hash = ?
    LIMIT 1
  `).bind(hash).first();

  if (!account || account.status !== 'active') return null;

  const roleLevel = Number(account.role_level || 1);
  return {
    id: Number(account.id),
    label: account.label,
    roleLevel,
    owner: roleLevel >= ADMIN_ROLE_LEVELS.owner,
    session: false
  };
}

async function requireAdmin(request, env, minimumRole = 1, ownerOnly = false) {
  const admin = await getAdminIdentity(request, env);
  if (!admin) return { error: adminUnauthorized() };
  if (ownerOnly ? !admin.owner : admin.roleLevel < minimumRole) {
    return { error: adminForbidden() };
  }
  return { admin };
}

async function recordAdminLogin(env, adminId, request) {
  await env.users_db.batch([
    env.users_db.prepare(`
      UPDATE admin_accounts
      SET last_login_at = CURRENT_TIMESTAMP,
          login_count = login_count + 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(adminId),
    env.users_db.prepare(`
      INSERT INTO admin_login_events (admin_account_id, ip, user_agent)
      VALUES (?, ?, ?)
    `).bind(
      adminId,
      request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || null,
      request.headers.get('User-Agent') || ''
    )
  ]);
}

async function adminLogin(request, env) {
  const token = (request.headers.get('X-Admin-Token') || ((await readJson(request)) || {}).token || '').trim();
  if (!token) return adminUnauthorized();

  const rate = await takeRateLimit(env, clientKey(request, 'admin-login'), 20, 5 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const admin = await getAdminIdentity(request, env);
  if (!admin) return fail('unauthorized', 401, 'توکن مدیریت نامعتبر یا غیرفعال است.');

  await recordAdminLogin(env, admin.id, request);
  return json({
    success: true,
    admin: {
      id: admin.id,
      label: admin.label,
      roleLevel: admin.roleLevel,
      owner: admin.owner
    }
  });
}

async function adminValidate(request, env) {
  const admin = await getAdminIdentity(request, env);
  if (!admin) return adminUnauthorized();

  return json({
    success: true,
    admin: {
      id: admin.id,
      label: admin.label,
      roleLevel: admin.roleLevel,
      owner: admin.owner
    }
  });
}

async function adminOwnerLogin(request, env) {
  const body = await readJson(request);
  const keyword = typeof (body && body.keyword) === 'string' ? body.keyword : '';
  const rate = await takeRateLimit(env, clientKey(request, 'admin-owner-login'), 5, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const expectedHash = String(env.OWNER_ADMIN_KEYWORD_HASH || OWNER_ADMIN_KEYWORD_HASH).trim();
  const suppliedHash = await sha256Hex(keyword);
  if (!keyword || suppliedHash !== expectedHash) {
    return fail('unauthorized', 401, 'کلید ویژه مالک نامعتبر است.');
  }

  await ensureAdminTables(env);
  const master = await env.users_db.prepare(
    'SELECT id, label FROM admin_accounts WHERE is_builtin = 1 LIMIT 1'
  ).first();
  if (!master) return fail('owner_unavailable', 503, MSG.server);

  const sessionToken = randomId(32);
  const sessionHash = await sha256Hex(sessionToken);

  await env.users_db.prepare(`
    INSERT INTO admin_sessions (token_hash, admin_account_id, expires_at)
    VALUES (?, ?, datetime('now', ?))
  `).bind(sessionHash, master.id, OWNER_SESSION_TTL).run();

  await recordAdminLogin(env, master.id, request);

  return json({
    success: true,
    token: sessionToken,
    admin: {
      id: master.id,
      label: master.label,
      roleLevel: 100,
      owner: true,
      expiresIn: OWNER_SESSION_TTL
    }
  });
}

async function adminListAdministrators(request, env) {
  const auth = await requireAdmin(request, env, ADMIN_ROLE_LEVELS.owner, true);
  if (auth.error) return auth.error;

  await ensureAdminTables(env);
  const { results } = await env.users_db.prepare(`
    SELECT id, label, role_level, status, is_builtin, created_at, updated_at, last_login_at, login_count
    FROM admin_accounts
    ORDER BY is_builtin DESC, id ASC
  `).all();

  return json({
    success: true,
    administrators: (results || []).map((r) => ({
      id: Number(r.id),
      label: r.label,
      roleLevel: Number(r.role_level || 1),
      status: r.status,
      builtin: !!r.is_builtin,
      createdAt: r.created_at || null,
      updatedAt: r.updated_at || null,
      lastLoginAt: r.last_login_at || null,
      loginCount: Number(r.login_count || 0)
    }))
  });
}

async function adminCreateAdministrator(request, env) {
  const auth = await requireAdmin(request, env, ADMIN_ROLE_LEVELS.owner, true);
  if (auth.error) return auth.error;

  const body = await readJson(request);
  const label = String(body && body.label || '').trim().slice(0, 80);
  const roleLevel = Number.parseInt(body && body.roleLevel, 10);

  if (!label) return fail('invalid_label', 400, 'برای ادمین جدید یک نام وارد کن.');
  if (![1, 2, 3].includes(roleLevel)) return fail('invalid_role', 400, 'سطح دسترسی باید بین ۱ تا ۳ باشد.');

  await ensureAdminTables(env);
  const countRow = await env.users_db.prepare('SELECT COUNT(*) AS n FROM admin_accounts WHERE is_builtin = 0').first();
  if (Number(countRow?.n || 0) >= 100) return fail('admin_limit_reached', 409, 'تعداد ادمین‌ها به حد مجاز رسیده است.');

  const token = randomId(32);
  const tokenHash = await sha256Hex(token);

  try {
    const result = await env.users_db.prepare(`
      INSERT INTO admin_accounts (label, token_hash, role_level, status, is_builtin)
      VALUES (?, ?, ?, 'active', 0)
    `).bind(label, tokenHash, roleLevel).run();

    const id = Number(result.meta?.last_row_id || 0);
    return json({
      success: true,
      admin: { id, label, roleLevel, status: 'active', builtin: false, loginCount: 0, lastLoginAt: null },
      token
    });
  } catch (e) {
    console.error('admin_create_failed', e);
    return fail('admin_create_failed', 500, MSG.server);
  }
}

async function adminSetAdministratorRole(request, env, adminId) {
  const auth = await requireAdmin(request, env, ADMIN_ROLE_LEVELS.owner, true);
  if (auth.error) return auth.error;
  const body = await readJson(request);
  const roleLevel = Number.parseInt(body && body.roleLevel, 10);
  if (![1, 2, 3].includes(roleLevel)) return fail('invalid_role', 400, 'سطح دسترسی باید بین ۱ تا ۳ باشد.');

  const target = await env.users_db.prepare('SELECT id, is_builtin FROM admin_accounts WHERE id = ?').bind(adminId).first();
  if (!target) return fail('admin_not_found', 404, 'ادمین پیدا نشد.');
  if (target.is_builtin) return fail('builtin_protected', 409, 'سطح دسترسی مالک اصلی قابل کاهش نیست.');

  await env.users_db.prepare(`
    UPDATE admin_accounts SET role_level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
  `).bind(roleLevel, adminId).run();

  return json({ success: true, roleLevel });
}

async function adminSetAdministratorStatus(request, env, adminId) {
  const auth = await requireAdmin(request, env, ADMIN_ROLE_LEVELS.owner, true);
  if (auth.error) return auth.error;
  const body = await readJson(request);
  const status = String(body && body.status || '');
  if (!['active', 'disabled'].includes(status)) return fail('invalid_status', 400, 'وضعیت ادمین نامعتبر است.');

  const target = await env.users_db.prepare('SELECT id, is_builtin FROM admin_accounts WHERE id = ?').bind(adminId).first();
  if (!target) return fail('admin_not_found', 404, 'ادمین پیدا نشد.');
  if (target.is_builtin) return fail('builtin_protected', 409, 'مالک اصلی را نمی‌توان غیرفعال کرد.');

  await env.users_db.prepare('UPDATE admin_accounts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(status, adminId).run();
  if (status === 'disabled') {
    await env.users_db.prepare('DELETE FROM admin_sessions WHERE admin_account_id = ?').bind(adminId).run();
  }

  return json({ success: true, status });
}

async function adminDeleteAdministrator(request, env, adminId) {
  const auth = await requireAdmin(request, env, ADMIN_ROLE_LEVELS.owner, true);
  if (auth.error) return auth.error;

  const target = await env.users_db.prepare('SELECT id, is_builtin FROM admin_accounts WHERE id = ?').bind(adminId).first();
  if (!target) return fail('admin_not_found', 404, 'ادمین پیدا نشد.');
  if (target.is_builtin) return fail('builtin_protected', 409, 'مالک اصلی را نمی‌توان حذف کرد.');

  await env.users_db.batch([
    env.users_db.prepare('DELETE FROM admin_sessions WHERE admin_account_id = ?').bind(adminId),
    env.users_db.prepare('DELETE FROM admin_login_events WHERE admin_account_id = ?').bind(adminId),
    env.users_db.prepare('DELETE FROM admin_accounts WHERE id = ?').bind(adminId)
  ]);

  return json({ success: true });
}

 async function adminListUsers(request, env) {
   const url = new URL(request.url);
   const limitParam = Number.parseInt(url.searchParams.get('limit') || '200', 10);
   const limit = Math.min(Math.max(Number.isFinite(limitParam) ? limitParam : 200, 1), 500);
   const search = (url.searchParams.get('search') || '').trim();

   await ensureGoogleIdentityTables(env);
   await ensureAccountSecurityTables(env);
   await ensureUserSettingsTable(env);

   let query = `
     SELECT
       u.id,
       u.display_id,
       u.status,
       u.trust_level,
       u.last_login,
       u.created_at,
       (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > datetime('now')) AS active_session_count,
       EXISTS(SELECT 1 FROM recovery_codes r WHERE r.user_id = u.id) AS has_recovery,
       EXISTS(SELECT 1 FROM account_passwords p WHERE p.user_id = u.id) AS has_password,
       EXISTS(SELECT 1 FROM google_identities g WHERE g.user_id = u.id) AS google_linked,
       (SELECT google_email FROM google_identities g WHERE g.user_id = u.id LIMIT 1) AS google_email,
       (SELECT last_viewed_at FROM recovery_code_views v WHERE v.user_id = u.id LIMIT 1) AS recovery_last_viewed_at,
       (SELECT created_at FROM recovery_codes r WHERE r.user_id = u.id LIMIT 1) AS recovery_created_at,
       (SELECT COUNT(*) FROM user_settings us WHERE us.user_id = u.id) AS setting_count
     FROM users u
   `;
   const binds = [];
   if (search) {
     query += ' WHERE u.display_id LIKE ? OR CAST(u.id AS TEXT) LIKE ? OR EXISTS(SELECT 1 FROM google_identities sg WHERE sg.user_id = u.id AND sg.google_email LIKE ?)';
     const q = '%' + search + '%';
     binds.push(q, q, q);
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
     activeSessionCount: Number(r.active_session_count || 0),
     hasRecovery: !!r.has_recovery,
     passwordSet: !!r.has_password,
     googleLinked: !!r.google_linked,
     googleEmail: r.google_email || null,
     recoveryLastViewedAt: r.recovery_last_viewed_at || null,
     recoveryCreatedAt: r.recovery_created_at || null,
     settingsCount: Number(r.setting_count || 0),
   }));
   return json({ success: true, users });
 }

 async function adminUserDetail(request, env, userId) {
   await ensureGoogleIdentityTables(env);
   await ensureAccountSecurityTables(env);
   await ensureUserSettingsTable(env);

   const user = await env.users_db
     .prepare('SELECT id, display_id, status, trust_level, last_login, created_at FROM users WHERE id = ?')
     .bind(userId)
     .first();
   if (!user) return fail('user_not_found', 404, MSG.noUser);

   const [sessions, google, password, recovery, recoveryView, settingsRows] = await Promise.all([
     env.users_db.prepare("SELECT expires_at, user_agent FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY expires_at ASC").bind(userId).all(),
     env.users_db.prepare('SELECT google_email FROM google_identities WHERE user_id = ? LIMIT 1').bind(userId).first(),
     env.users_db.prepare('SELECT created_at, updated_at FROM account_passwords WHERE user_id = ? LIMIT 1').bind(userId).first(),
     env.users_db.prepare('SELECT created_at FROM recovery_codes WHERE user_id = ? LIMIT 1').bind(userId).first(),
     env.users_db.prepare('SELECT last_viewed_at FROM recovery_code_views WHERE user_id = ? LIMIT 1').bind(userId).first(),
     env.users_db.prepare('SELECT setting_key, setting_value, updated_at FROM user_settings WHERE user_id = ? ORDER BY setting_key ASC').bind(userId).all(),
   ]);

   const settings = {};
   for (const row of (settingsRows.results || [])) {
     settings[row.setting_key] = { value: row.setting_value, updatedAt: row.updated_at || null };
   }

   const activeSessions = sessions.results || [];
   return json({
     success: true,
     user: {
       id: user.id,
       displayId: user.display_id,
       status: user.status,
       trustLevel: user.trust_level,
       lastLogin: user.last_login || null,
       createdAt: user.created_at || null,
       googleLinked: !!google,
       googleEmail: google?.google_email || null,
       passwordSet: !!password,
       passwordUpdatedAt: password?.updated_at || password?.created_at || null,
       hasRecovery: !!recovery,
       recoveryCreatedAt: recovery?.created_at || null,
       recoveryLastViewedAt: recoveryView?.last_viewed_at || null,
       activeSessionCount: activeSessions.length,
       sessions: activeSessions.map((r) => ({
         expiresAt: r.expires_at || null,
         userAgent: r.user_agent || '',
       })),
       settings,
       settingCount: Object.keys(settings).length,
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
        const clientId = String(env.GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID || '').trim();
        if (!clientId) return fail('google_not_configured', 503, MSG.googleNotConfigured);
        return json({ success: true, clientId });
      }
      if (path === '/api/auth/google/link' && method === 'POST') return await linkGoogle(request, env);
      if (path === '/api/auth/google/signup' && method === 'POST') return await googleSignup(request, env);
      if (path === '/api/auth/google/signup/check' && method === 'POST') return await googleSignupCheck(request, env);
      if (path === '/api/auth/google/login' && method === 'POST') return await googleLogin(request, env);
      if (path === '/api/auth/password/setup' && method === 'POST') return await passwordSetup(request, env);
      if (path === '/api/auth/recovery/view' && method === 'POST') return await recoveryView(request, env);
      if (path === '/api/auth/settings' && method === 'GET') return await getUserSettings(request, env);
      if (path === '/api/auth/settings' && method === 'PUT') return await saveUserSetting(request, env);
      if (path === '/api/auth/me' && method === 'GET') return await me(request, env);
      if (path === '/api/auth/logout' && method === 'POST') return await logout(request, env);

      // ----- owner/admin endpoints -----
      if (path === '/api/admin/login' && method === 'POST') {
        return await adminLogin(request, env);
      }
      if (path === '/api/admin/validate' && method === 'POST') {
        return await adminValidate(request, env);
      }
      if (path === '/api/admin/owner/login' && method === 'POST') {
        return await adminOwnerLogin(request, env);
      }

      if (path.startsWith('/api/admin/')) {
        if (path === '/api/admin/administrators' && method === 'GET') {
          return await adminListAdministrators(request, env);
        }
        if (path === '/api/admin/administrators' && method === 'POST') {
          return await adminCreateAdministrator(request, env);
        }

        const adminId = parseAdminAccountId(path);
        if (adminId !== null) {
          if (path === `/api/admin/administrators/${adminId}/role` && method === 'POST') {
            return await adminSetAdministratorRole(request, env, adminId);
          }
          if (path === `/api/admin/administrators/${adminId}/status` && method === 'POST') {
            return await adminSetAdministratorStatus(request, env, adminId);
          }
          if (path === `/api/admin/administrators/${adminId}` && method === 'DELETE') {
            return await adminDeleteAdministrator(request, env, adminId);
          }
          return fail('not_found', 404, MSG.notFound);
        }

        const auth = await getAdminIdentity(request, env);
        if (!auth) return adminUnauthorized();

        if (path === '/api/admin/users' && method === 'GET') {
          if (auth.roleLevel < ADMIN_ROLE_LEVELS.viewer) return adminForbidden();
          return await adminListUsers(request, env);
        }

        const userId = parseUserId(path);
        if (!userId) return fail('not_found', 404, MSG.notFound);

        if (path === `/api/admin/users/${encodeURIComponent(userId)}` && method === 'GET') {
          if (auth.roleLevel < ADMIN_ROLE_LEVELS.viewer) return adminForbidden();
          return await adminUserDetail(request, env, userId);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/status` && method === 'POST') {
          if (auth.roleLevel < ADMIN_ROLE_LEVELS.admin) return adminForbidden();
          const body = await readJson(request);
          return await adminSetUserStatus(env, userId, body && body.status);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/revoke-sessions` && method === 'POST') {
          if (auth.roleLevel < ADMIN_ROLE_LEVELS.admin) return adminForbidden();
          return await adminRevokeSessions(env, userId);
        }
        if (path === `/api/admin/users/${encodeURIComponent(userId)}/recovery/regenerate` && method === 'POST') {
          if (auth.roleLevel < ADMIN_ROLE_LEVELS.admin) return adminForbidden();
          return await adminRegenerateRecovery(env, userId);
        }

        return fail('not_found', 404, MSG.notFound);
      }

      // ----- recovery endpoints -----
      if (path === '/api/auth/recovery/login' && method === 'POST') return await recoveryLogin(request, env);
      if (path === '/api/auth/recovery/regenerate' && method === 'POST') return await recoveryRegenerate(request, env);

      return fail('not_found', 404, MSG.notFound);
    } catch (e) {
      console.error(e);
      return fail('server_error', 500, MSG.server, { detail: String((e && e.message) || e) });
    }
  },
};

// ==================================================
/* Google primary authentication */
async function googleSignup(request, env) {
  const body = await readJson(request);
  const passwordError = validatePasswordInput(body && body.password, body && body.passwordConfirm);
  if (passwordError) return fail(passwordError.error, 400, MSG[passwordError.error] || MSG.generic);
  const google = await verifyGoogleIdToken(body && body.googleIdToken, env);
  if (google.error) {
    return fail(
      google.error,
      google.error === 'google_not_configured' ? 503 : 401,
      google.error === 'google_not_configured' ? MSG.googleNotConfigured : MSG.googleInvalid
    );
  }

  await ensureGoogleIdentityTables(env);
  await ensureAccountSecurityTables(env);

  const rate = await takeRateLimit(env, 'google-signup:' + google.sub, 6, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const existing = await env.users_db
    .prepare('SELECT user_id FROM google_identities WHERE google_sub = ?')
    .bind(google.sub)
    .first();
  if (existing) return fail('google_account_exists', 409, MSG.googleAccountExists);

  let displayId = null;
  for (let i = 0; i < 10; i++) {
    const id = generateDisplayId();
    const exists = await env.users_db.prepare('SELECT id FROM users WHERE display_id = ?').bind(id).first();
    if (!exists) { displayId = id; break; }
  }
  if (!displayId) return fail('id_generation_failed', 500, MSG.server);
  const recoveryCode = generateRecoveryCode();
  const recoveryHash = await sha256Hex(normalizeRecoveryCode(recoveryCode));
  const passwordPackage = await preparePasswordPackage(body.password, recoveryCode);

  try {
    await env.users_db.batch([
      env.users_db.prepare('INSERT INTO users (display_id, status, trust_level) VALUES (?, ?, ?)').bind(displayId, 'active', 'new'),
      env.users_db.prepare('INSERT INTO google_identities (user_id, google_sub, google_email) VALUES ((SELECT id FROM users WHERE display_id = ?), ?, ?)').bind(displayId, google.sub, google.email),
      env.users_db.prepare('INSERT INTO account_passwords (user_id, salt, password_hash, iterations) VALUES ((SELECT id FROM users WHERE display_id = ?), ?, ?, ?)').bind(displayId, passwordPackage.salt, passwordPackage.passwordHash, passwordPackage.iterations),
      env.users_db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES ((SELECT id FROM users WHERE display_id = ?), ?) ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, created_at = CURRENT_TIMESTAMP').bind(displayId, recoveryHash),
      env.users_db.prepare('INSERT INTO recovery_code_secrets (user_id, iv, ciphertext) VALUES ((SELECT id FROM users WHERE display_id = ?), ?, ?)').bind(displayId, passwordPackage.iv, passwordPackage.ciphertext)
    ]);
  } catch (e) {
    const again = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE google_sub = ?').bind(google.sub).first();
    if (again) return fail('google_account_exists', 409, MSG.googleAccountExists);
    console.error('google_signup_create_failed', e);
    return fail('user_create_failed', 500, MSG.server, { detail: String((e && e.message) || e) });
  }

  const user = await env.users_db.prepare('SELECT id, display_id FROM users WHERE display_id = ?').bind(displayId).first();
  if (!user) return fail('user_create_failed', 500, MSG.server);

  const token = await createSession(env, user.id, request);
  return json({
    success: true,
    token,
    user: { id: user.id, displayId: user.display_id },
    passwordConfigured: true,
    recoveryReady: true,
    googleLinked: true,
  });
}
async function googleSignupCheck(request, env) {
  const body = await readJson(request);
  const google = await verifyGoogleIdToken(body && body.googleIdToken, env);
  if (google.error) {
    return fail(
      google.error,
      google.error === 'google_not_configured' ? 503 : 401,
      google.error === 'google_not_configured' ? MSG.googleNotConfigured : MSG.googleInvalid
    );
  }

  await ensureGoogleIdentityTables(env);

  const rate = await takeRateLimit(env, 'google-signup-check:' + google.sub, 10, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const existing = await env.users_db
    .prepare('SELECT user_id FROM google_identities WHERE google_sub = ?')
    .bind(google.sub)
    .first();

  if (existing) return fail('google_account_exists', 409, MSG.googleAccountExists);

  return json({ success: true, available: true });
}

async function googleLogin(request, env) {
  const body = await readJson(request);
  const google = await verifyGoogleIdToken(body && body.googleIdToken, env);
  if (google.error) {
    return fail(
      google.error,
      google.error === 'google_not_configured' ? 503 : 401,
      google.error === 'google_not_configured' ? MSG.googleNotConfigured : MSG.googleInvalid
    );
  }

  await ensureGoogleIdentityTables(env);

  const rate = await takeRateLimit(env, 'google-login:' + google.sub, 20, 10 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const row = await env.users_db
    .prepare('SELECT user_id FROM google_identities WHERE google_sub = ?')
    .bind(google.sub)
    .first();
  if (!row) return fail('google_account_not_linked', 404, MSG.googleAccountNotLinked);

  const user = await env.users_db
    .prepare('SELECT id, display_id, status FROM users WHERE id = ?')
    .bind(row.user_id)
    .first();
  if (!user) return fail('user_not_found', 404, MSG.noUser);
  if (user.status !== 'active') return fail('account_disabled', 403, MSG.disabled);

  await env.users_db
    .prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
    .bind(user.id)
    .run();

  const token = await createSession(env, user.id, request);
  return json({ success: true, token, user: { id: user.id, displayId: user.display_id }, googleLinked: true });
}

// ==================================================
// 7) SESSION (me / logout)
// ==================================================
async function me(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;
  await ensureAccountSecurityTables(env);

  let googleLinked = false;
  try {
    await ensureGoogleIdentityTables(env);
    const g = await env.users_db.prepare('SELECT user_id FROM google_identities WHERE user_id = ?').bind(s.user.id).first();
    googleLinked = !!g;
  } catch (e) {
    googleLinked = false;
  }

  let hasRecovery = false;
  let passwordConfigured = false;
  let recoveryReady = false;
  try {
    const r = await env.users_db.prepare('SELECT user_id FROM recovery_codes WHERE user_id = ?').bind(s.user.id).first();
    hasRecovery = !!r;
    const p = await env.users_db.prepare('SELECT user_id FROM account_passwords WHERE user_id = ?').bind(s.user.id).first();
    passwordConfigured = !!p;
    const rs = await env.users_db.prepare('SELECT user_id FROM recovery_code_secrets WHERE user_id = ?').bind(s.user.id).first();
    recoveryReady = !!rs;
  } catch (e) {
    hasRecovery = false;
    passwordConfigured = false;
    recoveryReady = false;
  }

  return json({
    success: true,
    user: {
      id: s.user.id,
      displayId: s.user.displayId,
      status: s.user.status,
      hasRecovery,
      passwordConfigured,
      recoveryReady,
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
// login with recovery code; the same code remains valid for this account
async function passwordSetup(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;
  const rate = await takeRateLimit(env, 'password-setup:' + s.user.id, 4, 15 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const body = await readJson(request);
  const passwordError = validatePasswordInput(body && body.password, body && body.passwordConfirm);
  if (passwordError) return fail(passwordError.error, 400, MSG[passwordError.error] || MSG.generic);

  await ensureAccountSecurityTables(env);
  const existing = await env.users_db.prepare('SELECT user_id FROM account_passwords WHERE user_id = ?').bind(s.user.id).first();
  if (existing) return fail('password_already_set', 409, MSG.passwordAlreadySet);

  const recoveryCode = generateRecoveryCode();
  const recoveryHash = await sha256Hex(normalizeRecoveryCode(recoveryCode));
  const passwordPackage = await preparePasswordPackage(body.password, recoveryCode);

  try {
    await env.users_db.batch([
      env.users_db.prepare('INSERT INTO account_passwords (user_id, salt, password_hash, iterations) VALUES (?, ?, ?, ?)').bind(s.user.id, passwordPackage.salt, passwordPackage.passwordHash, passwordPackage.iterations),
      env.users_db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, created_at = CURRENT_TIMESTAMP').bind(s.user.id, recoveryHash),
      env.users_db.prepare('INSERT INTO recovery_code_secrets (user_id, iv, ciphertext) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET iv = excluded.iv, ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP').bind(s.user.id, passwordPackage.iv, passwordPackage.ciphertext)
    ]);
  } catch (e) {
    const again = await env.users_db.prepare('SELECT user_id FROM account_passwords WHERE user_id = ?').bind(s.user.id).first();
    if (again) return fail('password_already_set', 409, MSG.passwordAlreadySet);
    console.error('password_setup_failed', e);
    return fail('server_error', 500, MSG.server);
  }
  return json({ success: true, passwordConfigured: true, recoveryReady: true });
}

async function recoveryView(request, env) {
  const s = await getSessionUser(request, env);
  if (s.error) return s.error;

  const rate = await takeRateLimit(env, 'recovery-view:' + s.user.id, 8, 15 * 60 * 1000);
  if (!rate.allowed) return fail('rate_limited', 429, MSG.rateLimited, { retryAfter: rate.retryAfter });

  const body = await readJson(request);
  const password = body && typeof body.password === 'string' ? body.password : '';
  const passwordConfirm = body && typeof body.passwordConfirm === 'string' ? body.passwordConfirm : '';
  if (!password || !passwordConfirm) return fail('password_required', 400, MSG.passwordRequired);
  if (password !== passwordConfirm) return fail('password_mismatch', 400, MSG.passwordMismatch);

  await ensureAccountSecurityTables(env);

  async function cooldownInfo() {
    return await env.users_db.prepare(`
      SELECT
        datetime(last_viewed_at, '+1 day') AS next_allowed_at,
        MAX(1, CAST(strftime('%s', datetime(last_viewed_at, '+1 day')) - strftime('%s', 'now') AS INTEGER)) AS retry_after
      FROM recovery_code_views
      WHERE user_id = ?
    `).bind(s.user.id).first();
  }

  const cooldown = await cooldownInfo();
  if (cooldown && Number(cooldown.retry_after || 0) > 0) {
    return fail('recovery_view_cooldown', 429, MSG.recoveryViewCooldown, {
      retryAfter: Number(cooldown.retry_after),
      nextAllowedAt: cooldown.next_allowed_at
    });
  }

  const pw = await env.users_db.prepare('SELECT salt, password_hash, iterations FROM account_passwords WHERE user_id = ?').bind(s.user.id).first();
  if (!pw) return fail('password_not_set', 409, MSG.passwordNotSet);

  const candidate = await derivePasswordHash(password, pw.salt, Number(pw.iterations) || PASSWORD_ITERATIONS);
  if (candidate !== pw.password_hash) return fail('password_invalid', 401, MSG.passwordInvalid);

  const secret = await env.users_db.prepare('SELECT iv, ciphertext FROM recovery_code_secrets WHERE user_id = ?').bind(s.user.id).first();
  if (!secret) return fail('recovery_code_unavailable', 409, MSG.recoveryCodeUnavailable);

  let recoveryCode;
  try {
    recoveryCode = await decryptRecoveryCode(password, pw.salt, Number(pw.iterations) || PASSWORD_ITERATIONS, secret.iv, secret.ciphertext);
  } catch (e) {
    console.error('recovery_decrypt_failed', e);
    return fail('recovery_code_unavailable', 409, MSG.recoveryCodeUnavailable);
  }

  const hash = await sha256Hex(normalizeRecoveryCode(recoveryCode));
  const stored = await env.users_db.prepare('SELECT code_hash FROM recovery_codes WHERE user_id = ?').bind(s.user.id).first();
  if (!stored || stored.code_hash !== hash) return fail('recovery_code_unavailable', 409, MSG.recoveryCodeUnavailable);

  const claim = await env.users_db.prepare(`
    INSERT INTO recovery_code_views (user_id, last_viewed_at)
    VALUES (?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET
      last_viewed_at = excluded.last_viewed_at
    WHERE recovery_code_views.last_viewed_at <= datetime('now', '-1 day')
  `).bind(s.user.id).run();

  if (Number((claim.meta && claim.meta.changes) || 0) !== 1) {
    const retry = await cooldownInfo();
    return fail('recovery_view_cooldown', 429, MSG.recoveryViewCooldown, {
      retryAfter: Number((retry && retry.retry_after) || 86400),
      nextAllowedAt: retry && retry.next_allowed_at
    });
  }

  return json({ success: true, recoveryCode, permanent: true });
}

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

  await env.users_db
    .prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
    .bind(user.id)
    .run();
  const token = await createSession(env, user.id, request);

  return json({
    success: true,
    token,
    user: { id: user.id, displayId: user.display_id },
    recoveryReady: true,
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


