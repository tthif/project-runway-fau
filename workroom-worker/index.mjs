const tokenUrl = 'https://oauth2.googleapis.com/token';
const firestoreUrl = 'https://firestore.googleapis.com/v1';
const encoder = new TextEncoder();
let cachedToken;

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

async function readResponse(response, operation) {
  if (!response.ok) throw new Error(`${operation}: HTTP ${response.status}`);
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

export async function updateCounter(env) {
  const token = await getAccessToken(env);
  const documents = `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`;
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const firestore = (suffix, options) => fetch(`${firestoreUrl}/${documents}${suffix}`, { headers, ...options });
  const post = async (method, body) => readResponse(await firestore(`:${method}`, {
    method: 'POST',
    body: JSON.stringify(body),
  }), `Firestore ${method}`);

  const { transaction } = await post('beginTransaction', { options: { readWrite: {} } });
  const getDocument = async path => {
    const response = await firestore(`/${path}?transaction=${encodeURIComponent(transaction)}`);
    return response.status === 404 ? {} : documentFields(await readResponse(response, 'Firestore get'));
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
    if (!state.rodada) return false;
    const rodada = String(state.rodada);
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
    if (String(published.rodada) === rodada && published.enviados === enviados && published.total === total) return false;

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
  async scheduled(_event, env) {
    try {
      await updateCounter(env);
    } catch (error) {
      console.error(error.message);
      throw error;
    }
  },
};
