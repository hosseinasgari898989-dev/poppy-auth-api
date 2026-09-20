// ==================================================
// Poppy Auth API  |  src/index.js
// Cloudflare Workers + D1 (binding: users_db)
// @simplewebauthn/server v11+ (v11 / v12 / v13)
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

// Only these origins may register / login.
// Add your main site origin here (no trailing slash).
const ALLOWED_ORIGINS = [
  'https://hosseinasgari898989-dev.github.io',
  // 'https://YOUR-MAIN-SITE',
];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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

function getOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin || origin === 'null') return null;
  return ALLOWED_ORIGINS.includes(origin) ? origin : null;
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

// ==================================================
// 3) DB HELPERS
// ==================================================
async function cleanup(env) {
  await env.users_db.batch([
    env.users_db.prepare("DELETE FROM challenges WHERE expires_at < datetime('now')"),
    env.users_db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')"),
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

      return json({ error: 'not_found' }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: 'server_error', detail: String((e && e.message) || e) }, 500);
    }
  },
};

// ==================================================
// 5) REGISTER
// ==================================================
async function registerBegin(request, env) {
  const origin = getOrigin(request);
  if (!origin) return json({ error: 'origin_not_allowed' }, 403);
  const rpId = new URL(origin).hostname;

  // v11+: userID must be bytes (Uint8Array)
  const userHandle = crypto.getRandomValues(new Uint8Array(16));
  const userHandleB64 = b64uEncode(userHandle);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userID: userHandle,
    userName: 'poppy-' + userHandleB64.slice(0, 6),
    userDisplayName: 'Poppy User',
    attestationType: 'none',
    timeout: WEBAUTHN_TIMEOUT,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  const challengeId = randomId(16);
  await saveChallenge(env, {
    id: challengeId,
    userId: userHandleB64,
    challenge: options.challenge,
    type: 'register',
    origin,
    rpId,
  });

  return json({ success: true, options, challengeId });
}

async function registerFinish(request, env) {
  const body = await readJson(request);
  const { challengeId, credential } = body || {};
  if (!challengeId || !credential) return json({ error: 'missing_fields' }, 400);

  const ch = await takeChallenge(env, challengeId, 'register');
  if (!ch) return json({ error: 'challenge_not_found_or_expired' }, 400);

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
    return json({ error: 'verification_failed: ' + e.message }, 400);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return json({ error: 'not_verified' }, 400);
  }

  // v11+: data lives in registrationInfo.credential
  const cred = verification.registrationInfo.credential;
  if (!cred || !cred.id || !cred.publicKey) {
    return json({ error: 'bad_registration_info' }, 500);
  }
  const credentialIdB64 = cred.id;
  const publicKeyB64 = b64uEncode(cred.publicKey);
  const counter = cred.counter || 0;

  const dup = await env.users_db
    .prepare('SELECT credential_id FROM credentials WHERE credential_id = ?')
    .bind(credentialIdB64)
    .first();
  if (dup) return json({ error: 'credential_already_registered' }, 409);

  let displayId = null;
  for (let i = 0; i < 10; i++) {
    const id = generateDisplayId();
    const exists = await env.users_db
      .prepare('SELECT id FROM users WHERE display_id = ?')
      .bind(id)
      .first();
    if (!exists) {
      displayId = id;
      break;
    }
  }
  if (!displayId) return json({ error: 'id_generation_failed' }, 500);

  const userAgent = request.headers.get('User-Agent') || '';

  // user + credential in one transaction
  await env.users_db.batch([
    env.users_db
      .prepare('INSERT INTO users (display_id, status, trust_level) VALUES (?, ?, ?)')
      .bind(displayId, 'active', 'new'),
    env.users_db
      .prepare(
        'INSERT INTO credentials (credential_id, user_id, public_key, counter, device_info) VALUES (?, (SELECT id FROM users WHERE display_id = ?), ?, ?, ?)'
      )
      .bind(credentialIdB64, displayId, publicKeyB64, counter, userAgent),
  ]);

  const user = await env.users_db
    .prepare('SELECT id, display_id FROM users WHERE display_id = ?')
    .bind(displayId)
    .first();
  if (!user) return json({ error: 'user_create_failed' }, 500);

  const token = await createSession(env, user.id, request);

  return json({ success: true, token, user: { id: user.id, displayId: user.display_id } });
}

// ==================================================
// 6) LOGIN
// ==================================================
async function loginBegin(request, env) {
  const origin = getOrigin(request);
  if (!origin) return json({ error: 'origin_not_allowed' }, 403);
  const rpId = new URL(origin).hostname;

  // empty allowCredentials = discoverable passkey (browser shows account picker)
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    userVerification: 'required',
    timeout: WEBAUTHN_TIMEOUT,
  });

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
  const body = await readJson(request);
  const { challengeId, credential } = body || {};
  if (!challengeId || !credential || !credential.id) return json({ error: 'missing_fields' }, 400);

  const ch = await takeChallenge(env, challengeId, 'login');
  if (!ch) return json({ error: 'challenge_not_found_or_expired' }, 400);

  const storedCred = await env.users_db
    .prepare('SELECT * FROM credentials WHERE credential_id = ?')
    .bind(credential.id)
    .first();
  if (!storedCred) return json({ error: 'credential_not_found' }, 400);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: ch.origin,
      expectedRPID: ch.rp_id,
      credential: {
        id: storedCred.credential_id,
        publicKey: b64uDecode(storedCred.public_key),
        counter: storedCred.counter || 0,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    return json({ error: 'verification_failed: ' + e.message }, 400);
  }
  if (!verification.verified) return json({ error: 'not_verified' }, 400);

  const user = await env.users_db
    .prepare('SELECT * FROM users WHERE id = ?')
    .bind(storedCred.user_id)
    .first();
  if (!user) return json({ error: 'user_not_found' }, 400);
  if (user.status !== 'active') return json({ error: 'account_disabled' }, 403);

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

// ==================================================
// 7) SESSION (me / logout)
// ==================================================
async function me(request, env) {
  const token = getToken(request);
  if (!token) return json({ error: 'no_token' }, 401);

  const row = await env.users_db
    .prepare(
      "SELECT s.user_id, u.display_id, u.status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > datetime('now')"
    )
    .bind(token)
    .first();
  if (!row) return json({ error: 'invalid_token' }, 401);
  if (row.status !== 'active') return json({ error: 'account_disabled' }, 403);

  return json({
    success: true,
    user: { id: row.user_id, displayId: row.display_id, status: row.status },
  });
}

async function logout(request, env) {
  const token = getToken(request);
  if (token) {
    await env.users_db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return json({ success: true });
}
