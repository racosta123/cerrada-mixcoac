/* Helpers de solo-LECTURA para hablar con Firestore vía REST usando una service account.
   Compartido por migrar-categorias.js y respaldo-diagnostico.js.

   Requiere las variables de entorno FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   (las mismas credenciales de la service account que usa el Worker — NUNCA
   las pongas en un archivo del repo). */

function b64url(str){ return bytesToB64url(new TextEncoder().encode(str)); }
function bytesToB64url(bytes){
  let bin=''; for (const b of bytes) bin+=String.fromCharCode(b);
  return Buffer.from(bin,'binary').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function pemToDer(pem){
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  return Buffer.from(b64,'base64');
}
async function importPKCS8(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey('pkcs8', der, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']);
}

// Nota: Firestore en modo nativo no acepta el scope "datastore.readonly" (eso es de
// Datastore modo legacy) — hace falta el scope completo "datastore" incluso para leer.
// Lo "solo lectura" de respaldo-diagnostico.js lo garantiza el código (nunca llama PATCH),
// no el scope del token.
async function saToken(scope = 'https://www.googleapis.com/auth/datastore'){
  const now = Math.floor(Date.now()/1000);
  const jwtHeader = b64url(JSON.stringify({ alg:'RS256', typ:'JWT' }));
  const jwtClaim = b64url(JSON.stringify({
    iss: process.env.SA_EMAIL,
    scope,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
  }));
  const key = await importPKCS8(process.env.SA_PRIVATE_KEY.replace(/\\n/g, '\n'));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${jwtHeader}.${jwtClaim}`));
  const assertion = `${jwtHeader}.${jwtClaim}.${bytesToB64url(new Uint8Array(sig))}`;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${assertion}`,
  });
  const d = await r.json();
  if (!d.access_token) throw new Error('No se pudo obtener token de la service account: ' + JSON.stringify(d));
  return d.access_token;
}

function fsBase(){ return `https://firestore.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT}/databases/(default)/documents`; }

async function listCollection(token, nombreColeccion){
  const docs = [];
  let pageToken = undefined;
  do {
    const url = new URL(`${fsBase()}/${nombreColeccion}`);
    url.searchParams.set('pageSize', '300');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error('Firestore list falló: ' + r.status + ' ' + await r.text());
    const d = await r.json();
    (d.documents || []).forEach(doc => docs.push(doc));
    pageToken = d.nextPageToken;
  } while (pageToken);
  return docs;
}

// Convierte un valor tipado de Firestore REST ({ stringValue, doubleValue, ... }) a JS plano.
function fsValue(v){
  if (v == null) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('doubleValue' in v) return v.doubleValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('booleanValue' in v) return v.booleanValue;
  if ('timestampValue' in v) return v.timestampValue;
  if ('nullValue' in v) return null;
  if ('mapValue' in v) return fsFields(v.mapValue.fields || {});
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fsValue);
  return v;
}
function fsFields(fields){
  const out = {};
  for (const k in fields) out[k] = fsValue(fields[k]);
  return out;
}
// Convierte un doc completo de Firestore REST a { id, ...camposPlanos }.
function fsDocToPlain(doc){
  return { id: doc.name.split('/').pop(), ...fsFields(doc.fields || {}) };
}

module.exports = { saToken, fsBase, listCollection, fsValue, fsFields, fsDocToPlain };
