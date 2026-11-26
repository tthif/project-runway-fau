const tokenUrl = 'https://oauth2.googleapis.com/token';
const firestoreUrl = 'https://firestore.googleapis.com/v1';
const firebaseKeysUrl = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let cachedToken;
let cachedKeys;

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decodeBase64url(value) {
  return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
}

async function verifyFirebaseUser(token, project) {
  if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token) || token.length > 4096) return null;
  const [header, payload, signature] = token.split('.');
  let keyInfo, claims;
  try {
    keyInfo = JSON.parse(decoder.decode(decodeBase64url(header)));
    claims = JSON.parse(decoder.decode(decodeBase64url(payload)));
  } catch {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (keyInfo?.alg !== 'RS256' || !keyInfo.kid ||
      claims?.iss !== `https://securetoken.google.com/${project}` || claims.aud !== project ||
      !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now ||
      typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 128 || claims.sub.includes('/') ||
      claims.firebase?.sign_in_provider === 'anonymous') return null;
  if (!cachedKeys || cachedKeys.expires <= now) {
    const response = await fetch(firebaseKeysUrl);
    const { keys } = await readResponse(response, 'Chaves de autenticação Firebase');
    const age = Number(response.headers.get('Cache-Control')?.match(/max-age=(\d+)/)?.[1] || 300);
    cachedKeys = { keys, expires: now + age };
  }
  const jwk = cachedKeys.keys.find(key => key.kid === keyInfo.kid);
  if (!jwk) return null;
  const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify']);
  const valid = await crypto.subtle.verify(algorithm, key, decodeBase64url(signature), encoder.encode(`${header}.${payload}`));
  return valid ? claims.sub : null;
}

async function readResponse(response, operation) {
  if (!response.ok) {
    throw Object.assign(new Error(`${operation}: HTTP ${response.status}`), { status: response.status });
  }
  return response.json();
}

async function getAccessToken(env) {
  const credentials = JSON.parse(env.FIRESTORE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken?.keyId === credentials.private_key_id && cachedToken?.expiry > now + 60) {
    return cachedToken.value;
  }
  if (!credentials.client_email || !credentials.private_key || !credentials.private_key_id ||
      credentials.project_id !== env.FIREBASE_PROJECT) {
    throw new Error('Credencial do contador incompatível com o projeto.');
  }

  const header = { alg: 'RS256', typ: 'JWT', kid: credentials.private_key_id };
  const claims = {
    iss: credentials.client_email,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: tokenUrl,
    iat: now,
    exp: now + 3600,
  };
  const encode = value => base64url(encoder.encode(JSON.stringify(value)));
  const message = `${encode(header)}.${encode(claims)}`;
  const pem = credentials.private_key.replace(/-----[^-]+-----|\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), char => char.charCodeAt(0)),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(message));
  const result = await readResponse(await fetch(tokenUrl, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${message}.${base64url(signature)}`,
    }),
  }), 'Autenticação Firestore');
  if (!result.access_token) throw new Error('O Google não retornou um token de acesso.');
  cachedToken = { value: result.access_token, keyId: credentials.private_key_id, expiry: now + Number(result.expires_in) };
  return cachedToken.value;
}

function documentFields(document) {
  return Object.fromEntries(Object.entries(document?.fields || {}).map(([name, value]) => [
    name, value.stringValue ?? value.booleanValue ?? value.doubleValue ??
      (value.integerValue === undefined ? null : Number(value.integerValue)),
  ]));
}

function firestoreValue(value) {
  return Number.isInteger(value) ? { integerValue: String(value) } : { stringValue: String(value) };
}

function isEligible(profile) {
  return !profile.disabled && !profile.out && !profile.eliminado &&
    profile.ativo !== false && String(profile.status || '').toUpperCase() !== 'OUT';
}

export async function updateCounter(env, refresh) {
  const token = await getAccessToken(env);
  const documents = `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`;
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const firestore = (suffix, options) => fetch(`${firestoreUrl}/${documents}${suffix}`, { headers, ...options });
  const post = async (method, body) => readResponse(await firestore(`:${method}`, {
    method: 'POST',
    body: JSON.stringify(body),
  }), `Firestore ${method}`);

  const { transaction } = await post('beginTransaction', { options: { readWrite: {} } });
  const getDocument = async (path, fields = []) => {
    const query = new URLSearchParams({ transaction });
    fields.forEach(field => query.append('mask.fieldPaths', field));
    const response = await firestore(`/${path}?${query}`);
    return response.status === 404 ? null : documentFields(await readResponse(response, 'Firestore get'));
  };
  const query = async (collectionId, fieldPath, values, fields) => {
    const op = values.length === 1 ? 'EQUAL' : 'IN';
    const value = op === 'EQUAL' ? firestoreValue(values[0])
      : { arrayValue: { values: values.map(firestoreValue) } };
    const rows = await post('runQuery', {
      transaction,
      structuredQuery: {
        from: [{ collectionId }],
        where: { fieldFilter: { field: { fieldPath }, op, value } },
        select: { fields: fields.map(field => ({ fieldPath: field })) },
      },
    });
    return rows.filter(row => row.document).map(row => row.document);
  };

  let committed = false;
  try {
    const state = await getDocument('config/estado');
    if (!state?.rodada || !(Number(state.prazo) > Date.now())) return false;
    const rodada = String(state.rodada);
    if (refresh) {
      if (refresh.round !== rodada) return false;
      if (refresh.lookId) {
        const look = await getDocument(`looks/${encodeURIComponent(refresh.lookId)}`, ['uid', 'rodada', 't']);
        if (look?.uid !== refresh.uid || String(look.rodada) !== rodada ||
            !Number.isFinite(look.t) || Math.abs(Date.now() - look.t) > 120000) return false;
      }
      const profile = await getDocument(`perfis/${encodeURIComponent(refresh.uid)}`,
        ['role', 'disabled', 'out', 'eliminado', 'ativo', 'status']);
      if (profile?.role !== 'estilista' || !isEligible(profile)) return false;
    }
    const beauty = state.themeId === 'theme_beauty_eye';
    const rounds = /^\d+$/.test(rodada) && String(Number(rodada)) === rodada
      ? [rodada, Number(rodada)]
      : [state.rodada];
    const [published, profiles, looks, twist] = await Promise.all([
      getDocument('config/entregas_publicas'),
      query('perfis', 'role', ['estilista'], ['disabled', 'out', 'eliminado', 'ativo', 'status']),
      query('looks', 'rodada', rounds, ['uid', 'slot']),
      beauty ? getDocument(`beauty_dinamicas/${encodeURIComponent(rodada)}`) : null,
    ]);

    const released = ['assigned', 'exhibition'].includes(twist?.phase);
    const required = beauty ? (released ? 2 : 1) : state.fase === 'final' ? 4 : Number(state.numSubmissoes) || 1;
    const counts = new Map(profiles.filter(document => isEligible(documentFields(document)))
      .map(document => [document.name.split('/').at(-1), 0]));
    for (const document of looks) {
      const { uid, slot } = documentFields(document);
      if (counts.has(uid) && (!beauty || released || Number(slot || 1) === 1)) {
        counts.set(uid, counts.get(uid) + 1);
      }
    }
    const total = Number(rodada) === 2 || state.themeId === 'w02_new_form' ? Math.min(18, counts.size) : counts.size;
    const enviados = Math.min(total, [...counts.values()].filter(count => count >= required).length);
    if (String(published?.rodada) === rodada && published.enviados === enviados && published.total === total) return false;

    const fields = Object.fromEntries(Object.entries({ rodada, enviados, total })
      .map(([field, value]) => [field, firestoreValue(value)]));
    await post('commit', {
      transaction,
      writes: [{
        update: { name: `${documents}/config/entregas_publicas`, fields },
        updateMask: { fieldPaths: Object.keys(fields) },
        updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
      }],
    });
    committed = true;
    return true;
  } finally {
    if (!committed) await post('rollback', { transaction }).catch(() => {});
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const host = url.hostname.match(/^project-runway-fau-counter(\.[a-z0-9-]+\.workers\.dev)$/);
    if (url.pathname !== '/sync-workroom' || !host || origin !== `https://project-runway-fau${host[1]}`) {
      return new Response(null, { status: 404 });
    }
    const headers = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization',
      'Cache-Control': 'no-store',
      Vary: 'Origin',
    };
    const respond = status => new Response(null, { status, headers });
    if (request.method === 'OPTIONS') return respond(204);
    if (request.method !== 'POST') return respond(405);

    const round = url.searchParams.get('round');
    const lookId = url.searchParams.get('look');
    const auth = request.headers.get('Authorization');
    if (!round || round.length > 128 || !auth?.startsWith('Bearer ')) return respond(400);
    if (lookId !== null && !/^[a-zA-Z0-9_-]{1,200}$/.test(lookId)) return respond(400);
    try {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (!(await env.REQUEST_LIMIT.limit({ key: ip })).success) return respond(429);
      const uid = await verifyFirebaseUser(auth.slice(7), env.FIREBASE_PROJECT);
      if (!uid) return respond(401);
      const activityKey = lookId ? `submit:${uid}` : `visit:${uid}`;
      if (!(await env.DESIGNER_LIMIT.limit({ key: activityKey })).success) return respond(429);
      const refresh = { uid, round, lookId };
      try {
        await updateCounter(env, refresh);
      } catch (error) {
        if (error.status !== 409) throw error;
        await updateCounter(env, refresh);
      }
      return respond(204);
    } catch (error) {
      console.error(error.message);
      return respond(503);
    }
  },
  async scheduled(_event, env) {
    try {
      await updateCounter(env);
    } catch (error) {
      console.error(error.message);
      throw error;
    }
  },
};
