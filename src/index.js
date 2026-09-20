import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const RP_NAME = 'Poppy Playtime Archive';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function getOrigin(request) {
  const origin = request.headers.get('Origin');
  if (origin && origin !== 'null') return origin;
  return new URL(request.url).origin;
}

function getRpId(request) {
  const origin = getOrigin(request);
  try {
    return new URL(origin).hostname;
  } catch (e) {
    return new URL(request.url).hostname;
  }
}
function b64uEncode(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64uDecode(str) {
  str = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

function randomId(bytes = 16) {
  return b64uEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

function generateDisplayId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let id = '';
  for (let i = 0; i < 4; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return '#' + id;
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/' && request.method === 'GET') {
        return json({
          ok: true,
          service: 'poppy-auth-api',
          rpId: getRpId(request),
          time: new Date().toISOString(),
        });
      }

      if (path === '/api/auth/register/begin' && request.method === 'POST') {
        return await registerBegin(request, env);
      }
      if (path === '/api/auth/register/finish' && request.method === 'POST') {
        return await registerFinish(request, env);
      }
      if (path === '/api/auth/login/begin' && request.method === 'POST') {
        return await loginBegin(request, env);
      }
      if (path === '/api/auth/login/finish' && request.method === 'POST') {
        return await loginFinish(request, env);
      }
      if (path === '/api/auth/me' && request.method === 'GET') {
        return await me(request, env);
      }
      if (path === '/api/auth/logout' && request.method === 'POST') {
        return await logout(request, env);
      }

      return json({ error: 'not_found' }, 404);
    } catch (e) {
      console.error(e);
      return json({ error: e.message || 'server_error' }, 500);
    }
  },
};

// ============ Register ============

async function registerBegin(request, env) {
  const rpId = getRpId(request);
  const origin = getOrigin(request);
  const userId = randomId(16);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userID: b64uDecode(userId),
    userName: userId,
    userDisplayName: userId,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred',
    },
    excludeCredentials: [],
    supportedAlgorithmIDs: [-7, -257],
  });

  const challengeId = randomId(16);
  await env.users_db
    .prepare(
      'INSERT INTO challenges (id, user_id, challenge, type, origin, rp_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now", "+10 minutes"))'
    )
    .bind(challengeId, userId, options.challenge, 'register', origin, rpId)
    .run();

  return json({ success: true, options, challengeId });
}

async function registerFinish(request, env) {
  const body = await request.json();
  const { challengeId, credential } = body;

  if (!challengeId || !credential) {
    return json({ error: 'missing_fields' }, 400);
  }

  const ch = await env.users_db
    .prepare('SELECT * FROM challenges WHERE id = ? AND type = ?')
    .bind(challengeId, 'register')
    .first();

  if (!ch) return json({ error: 'challenge_not_found' }, 400);

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

  if (!verification.verified) {
    return json({ error: 'not_verified' }, 400);
  }

  // Generate unique display ID
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

  if (!displayId) {
    return json({ error: 'id_generation_failed' }, 500);
  }

  // Create user
  const userResult = await env.users_db
    .prepare('INSERT INTO users (display_id, status, trust_level) VALUES (?, ?, ?)')
    .bind(displayId, 'active', 'new')
    .run();

  const userId = userResult.meta.last_row_id;

  // Store credential
  const info = verification.registrationInfo;
  const publicKeyB64 = b64uEncode(info.credentialPublicKey);
  const credentialIdB64 = b64uEncode(info.credentialID);

  await env.users_db
    .prepare(
      'INSERT INTO credentials (credential_id, user_id, public_key, counter, device_info) VALUES (?, ?, ?, ?, ?)'
    )
    .bind(
      credentialIdB64,
      userId,
      publicKeyB64,
      info.counter,
      request.headers.get('User-Agent') || ''
    )
    .run();

  // Create session
  const token = randomId(32);
  await env.users_db
    .prepare(
      'INSERT INTO sessions (token, user_id, expires_at, user_agent) VALUES (?, ?, datetime("now", "+30 days"), ?)'
    )
    .bind(token, userId, request.headers.get('User-Agent') || '')
    .run();

  await env.users_db.prepare('DELETE FROM challenges WHERE id = ?').bind(challengeId).run();

  return json({
    success: true,
    token,
    user: { id: userId, displayId },
  });
}

// ============ Login ============

async function loginBegin(request, env) {
  const rpId = getRpId(request);
  const origin = getOrigin(request);

  const creds = await env.users_db
    .prepare('SELECT credential_id FROM credentials')
    .all();

  const allowCredentials = (creds.results || []).map((c) => ({
  id: c.credential_id,
  type: 'public-key',
}));

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials,
    userVerification: 'required',
  });

  const challengeId = randomId(16);
  await env.users_db
    .prepare(
      'INSERT INTO challenges (id, user_id, challenge, type, origin, rp_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now", "+10 minutes"))'
    )
    .bind(challengeId, '', options.challenge, 'login', origin, rpId)
    .run();

  return json({ success: true, options, challengeId });
}

async function loginFinish(request, env) {
  const body = await request.json();
  const { challengeId, credential } = body;

  if (!challengeId || !credential) {
    return json({ error: 'missing_fields' }, 400);
  }

  const ch = await env.users_db
    .prepare('SELECT * FROM challenges WHERE id = ? AND type = ?')
    .bind(challengeId, 'login')
    .first();

  if (!ch) return json({ error: 'challenge_not_found' }, 400);

  const storedCred = await env.users_db
    .prepare('SELECT * FROM credentials WHERE credential_id = ?')
    .bind(credential.id)
    .first();

  if (!storedCred) {
    return json({ error: 'credential_not_found' }, 400);
  }

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
        counter: storedCred.counter,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    return json({ error: 'verification_failed: ' + e.message }, 400);
  }

  if (!verification.verified) {
    return json({ error: 'not_verified' }, 400);
  }

  await env.users_db
    .prepare(
      'UPDATE credentials SET counter = ?, last_used = CURRENT_TIMESTAMP WHERE credential_id = ?'
    )
    .bind(verification.authenticationInfo.newCounter, storedCred.credential_id)
    .run();

  await env.users_db
    .prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?')
    .bind(storedCred.user_id)
    .run();

  const user = await env.users_db
    .prepare('SELECT * FROM users WHERE id = ?')
    .bind(storedCred.user_id)
    .first();

  const token = randomId(32);
  await env.users_db
    .prepare(
      'INSERT INTO sessions (token, user_id, expires_at, user_agent) VALUES (?, ?, datetime("now", "+30 days"), ?)'
    )
    .bind(token, storedCred.user_id, request.headers.get('User-Agent') || '')
    .run();

  await env.users_db.prepare('DELETE FROM challenges WHERE id = ?').bind(challengeId).run();

  return json({
    success: true,
    token,
    user: { id: user.id, displayId: user.display_id },
  });
}

// ============ Session ============

async function me(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();

  if (!token) return json({ error: 'no_token' }, 401);

  const row = await env.users_db
    .prepare(
      'SELECT s.user_id, u.display_id, u.status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP'
    )
    .bind(token)
    .first();

  if (!row) return json({ error: 'invalid_token' }, 401);

  return json({
    success: true,
    user: {
      id: row.user_id,
      displayId: row.display_id,
      status: row.status,
    },
  });
}

async function logout(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();

  if (token) {
    await env.users_db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }

  return json({ success: true });
}
