/* ===========================================================
   Cerrada Mixcoac · Cloudflare Worker (mixcoac-proxy)
   El ÚNICO que toca la Shelly. El cliente jamás ve la IP ni la llave.
   -----------------------------------------------------------
   Secrets (wrangler secret put ...):
     SHELLY_HOST          ej. http://192.168.1.50  (o túnel/IP pública segura)
     SHELLY_AUTH_KEY      auth key de Shelly (Gen2 RPC) o user:pass
     FIREBASE_PROJECT     cerrada-mixcoac
     SA_EMAIL             service account email (Admin)
     SA_PRIVATE_KEY       service account private key (PEM, con \n escapados)
     QR_SECRET            secreto para firmar/verificar tokens de QR
   Vars (wrangler.toml [vars]):
     ALLOWED_ORIGIN       https://racosta123.github.io
   =========================================================== */

const DOOR_CHANNELS = { visitantes:0, residentes:1, salida:2, peatones:3 };
const STAFF = new Set(['master','admin']);

export default {
  async fetch(req, env) {
    const origin = env.ALLOWED_ORIGIN || '*';
    if (req.method === 'OPTIONS') return cors(new Response(null,{status:204}), origin);

    const url = new URL(req.url);
    try {
      let out;
      switch (url.pathname) {
        case '/abrir':             out = await abrir(req, env); break;
        case '/invitacion/crear':  out = await crearInvitacion(req, env); break;
        case '/validar-qr':        out = await validarQR(req, env); break;  // lo llama el lector físico
        case '/finanzas/registrar': out = await registrarFinanza(req, env); break;
        case '/usuarios/crear':    out = await crearUsuario(req, env); break;
        case '/usuarios/suspender': out = await suspenderUsuario(req, env); break;
        default: out = json({ error:'Ruta no encontrada' }, 404);
      }
      return cors(out, origin);
    } catch (e) {
      return cors(json({ error: e.message || 'Error interno' }, e.status || 500), origin);
    }
  }
};

/* ============ /abrir — usuario autenticado abre una puerta ============ */
async function abrir(req, env) {
  const user = await requireAuth(req, env);
  const { puerta } = await req.json();
  if (!(puerta in DOOR_CHANNELS)) throw httpErr(400, 'Puerta no válida');

  const perfil = await getPerfil(env, user.uid);
  if (!perfil) throw httpErr(403, 'Sin perfil');
  // Un residente suspendido (por mora) no puede abrir; tampoco sus esclavos.
  if (perfil.suspendido) throw httpErr(403, 'Residente suspendido por mora');
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    const padre = await getPerfil(env, perfil.residenteUid);
    if (padre && padre.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');
  }
  // master, admin, residente y esclavo pueden abrir las 4 puertas.
  await triggerShelly(env, DOOR_CHANNELS[puerta]);

  const hogar = perfil.rol === 'residente' ? user.uid : (perfil.residenteUid || user.uid);
  await logApertura(env, {
    uid: user.uid, nombre: perfil.nombre, puerta, hogar, tipo:'app',
  });
  // Notifica al residente si quien abrió es su esclavo
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    await notificarResidente(env, perfil.residenteUid, `${perfil.nombre} usó ${puerta}`);
  }
  return json({ ok:true });
}

/* ============ /invitacion/crear — residente genera QR de visita ============ */
async function crearInvitacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !['residente','esclavo'].includes(perfil.rol))
    throw httpErr(403, 'Solo residentes pueden invitar');

  const { visitante, horas, usos, hogar } = await req.json();
  if (!visitante) throw httpErr(400, 'Falta el nombre del visitante');

  const ahora = Date.now();
  const expira = ahora + (Math.max(1, +horas||1) * 3600 * 1000);
  const jti = crypto.randomUUID();

  // Token firmado (HMAC) que viaja DENTRO del QR. El lector lo valida contra el Worker,
  // y además queda PRE-SINCRONIZADO en el lector para funcionar SIN internet en la cerrada.
  const payloadObj = { jti, exp: Math.floor(expira/1000), p:'visitantes', n: visitante };
  const payload = await signQR(env, payloadObj);

  // Guarda la invitación (fuente de verdad online)
  await firestoreSet(env, `invitaciones/${jti}`, {
    visitante: { stringValue: visitante },
    hogar: { stringValue: hogar || user.uid },
    creadaPor: { stringValue: user.uid },
    expira: { timestampValue: new Date(expira).toISOString() },
    usosRestantes: usos===0 ? { nullValue:null } : { integerValue: String(usos||1) },
    activa: { booleanValue: true },
  });

  // PRE-SINCRONIZA al lector físico (resiliencia offline). Si el lector no responde,
  // no bloquea: el QR sigue siendo válido online.
  await presyncReader(env, { jti, payload, exp: Math.floor(expira/1000), usos: usos||1 })
    .catch(()=>{});

  return json({ ok:true, payload, jti });
}

/* ============ /validar-qr — lo llama el LECTOR físico al escanear ============
   Funciona aunque el lector esté pre-sincronizado y sin internet (lógica local
   del lector). Cuando hay internet, valida y registra contra el Worker. */
async function validarQR(req, env) {
  // El lector se autentica con una llave propia (no un token de usuario)
  const readerKey = req.headers.get('X-Reader-Key');
  if (!env.READER_KEY || readerKey !== env.READER_KEY) throw httpErr(401, 'Lector no autorizado');

  const { payload } = await req.json();
  const data = await verifyQR(env, payload);          // verifica firma + expiración
  if (!data) throw httpErr(403, 'QR inválido o expirado');

  // Consume un uso de forma atómica
  const inv = await getInvitacion(env, data.jti);
  if (!inv || !inv.activa) throw httpErr(403, 'Invitación cancelada');
  // Si el residente del hogar está suspendido por mora, su QR no abre (sin gastar usos ni disparar la Shelly).
  const anfitrion = await getPerfil(env, inv.hogar);
  if (anfitrion && anfitrion.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');
  if (inv.usosRestantes !== null) {
    if (inv.usosRestantes <= 0) throw httpErr(403, 'Sin usos disponibles');
    await firestoreUpdate(env, `invitaciones/${data.jti}`, {
      usosRestantes: { integerValue: String(inv.usosRestantes - 1) },
    }, ['usosRestantes']);
  }

  await triggerShelly(env, DOOR_CHANNELS.visitantes);
  await logApertura(env, { uid:'qr', nombre:data.n, puerta:'visitantes', hogar:inv.hogar, tipo:'qr' });
  await notificarResidente(env, inv.hogar, `Visita ${data.n} entró por visitantes`);
  return json({ ok:true });
}

/* ============ /usuarios/suspender — solo staff, sobre residentes ============ */
async function suspenderUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'No autorizado');

  const { uid, suspendido } = await req.json();
  if (!uid || typeof suspendido !== 'boolean') throw httpErr(400, 'Datos inválidos');
  const objetivo = await getPerfil(env, uid);
  if (!objetivo) throw httpErr(404, 'Usuario no encontrado');
  if (objetivo.rol !== 'residente') throw httpErr(403, 'Solo se pueden suspender residentes');

  await firestoreUpdate(env, `usuarios/${uid}`, {
    suspendido: { booleanValue: suspendido },
  }, ['suspendido']);
  return json({ ok:true, uid, suspendido });
}

/* ============ /finanzas/registrar — solo master/admin ============ */
async function registrarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo master/admin registran finanzas');

  const { tipo, concepto, categoria, monto } = await req.json();
  if (!['ingreso','egreso'].includes(tipo)) throw httpErr(400, 'Tipo inválido');
  const m = Number(monto);
  if (!concepto || !(m > 0)) throw httpErr(400, 'Concepto o monto inválido');

  const id = crypto.randomUUID();
  await firestoreSet(env, `finanzas/${id}`, {
    tipo:{stringValue:tipo},
    concepto:{stringValue:String(concepto).slice(0,120)},
    categoria:{stringValue:String(categoria||'Otro').slice(0,40)},
    monto:{doubleValue:m},
    creadoPor:{stringValue:user.uid},
    creadoNombre:{stringValue:perfil.nombre||''},
    ts:{timestampValue:new Date().toISOString()},
  });
  return json({ ok:true, id });
}

/* ============ /usuarios/crear — solo staff, vía Admin ============ */
async function crearUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'No autorizado');

  const { nombre, email, password, rol, casa } = await req.json();
  if (!nombre || !email || !password || password.length < 8) throw httpErr(400, 'Datos inválidos');
  // admin NO puede crear master ni admin
  const permitidos = perfil.rol === 'master' ? ['admin','residente'] : ['residente'];
  if (!permitidos.includes(rol)) throw httpErr(403, 'Rol no permitido para tu cuenta');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  // Crea la cuenta de Auth vía Identity Toolkit
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts`, {
    method:'POST',
    headers:{ 'Authorization':'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ email, password, displayName: nombre, emailVerified:false }),
  });
  if (!res.ok) throw httpErr(400, 'No se pudo crear la cuenta (¿correo ya existe?)');
  const { localId } = await res.json();

  await firestoreSet(env, `usuarios/${localId}`, {
    nombre:{stringValue:nombre}, email:{stringValue:email},
    rol:{stringValue:rol}, ...(casa?{casa:{stringValue:casa}}:{}),
  }, at);
  return json({ ok:true, uid: localId });
}

/* ===========================================================
   SHELLY
   =========================================================== */
async function triggerShelly(env, channel) {
  // Shelly Gen2 RPC: dispara el relé del canal (pulso). Ajusta a tu modelo.
  const url = `${env.SHELLY_HOST}/rpc/Switch.Set?id=${channel}&on=true`;
  const headers = {};
  if (env.SHELLY_AUTH_KEY) headers['Authorization'] = 'Bearer ' + env.SHELLY_AUTH_KEY;
  const r = await fetch(url, { headers });
  if (!r.ok) throw httpErr(502, 'La cerradura no respondió');
}

/* ===========================================================
   FIREBASE AUTH — verificación de ID token (JWKS)
   =========================================================== */
let JWKS_CACHE = { keys:null, exp:0 };
async function requireAuth(req, env) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw httpErr(401, 'Falta token');
  return verifyIdToken(token, env);
}

async function verifyIdToken(token, env) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) throw httpErr(401, 'Token malformado');
  const header = JSON.parse(b64urlToStr(h));
  const claims = JSON.parse(b64urlToStr(p));

  const proj = env.FIREBASE_PROJECT;
  if (claims.aud !== proj) throw httpErr(401, 'aud inválido');
  if (claims.iss !== `https://securetoken.google.com/${proj}`) throw httpErr(401, 'iss inválido');
  if (claims.exp * 1000 < Date.now()) throw httpErr(401, 'Token expirado');

  const key = await getGooglePublicKey(header.kid);
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key,
    b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`)
  );
  if (!ok) throw httpErr(401, 'Firma inválida');
  return { uid: claims.user_id || claims.sub, email: claims.email };
}

async function getGooglePublicKey(kid) {
  if (!JWKS_CACHE.keys || Date.now() > JWKS_CACHE.exp) {
    const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
    const certs = await r.json();
    const maxAge = +(r.headers.get('cache-control')||'').match(/max-age=(\d+)/)?.[1] || 3600;
    JWKS_CACHE = { keys: certs, exp: Date.now() + maxAge*1000 };
  }
  const pem = JWKS_CACHE.keys[kid];
  if (!pem) throw httpErr(401, 'kid desconocido');
  return importX509(pem);
}

/* ===========================================================
   SERVICE ACCOUNT — token OAuth para Firestore/Identity (Admin)
   =========================================================== */
async function saToken(env, scope) {
  const now = Math.floor(Date.now()/1000);
  const jwtHeader = b64url(JSON.stringify({ alg:'RS256', typ:'JWT' }));
  const jwtClaim = b64url(JSON.stringify({
    iss: env.SA_EMAIL, scope, aud:'https://oauth2.googleapis.com/token',
    iat: now, exp: now+3600,
  }));
  const key = await importPKCS8(env.SA_PRIVATE_KEY.replace(/\\n/g,'\n'));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${jwtHeader}.${jwtClaim}`));
  const assertion = `${jwtHeader}.${jwtClaim}.${bytesToB64url(new Uint8Array(sig))}`;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${assertion}`,
  });
  const d = await r.json();
  if (!d.access_token) throw httpErr(500, 'SA token falló');
  return d.access_token;
}

/* ===========================================================
   FIRESTORE REST helpers (con service account)
   =========================================================== */
function fsBase(env){ return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`; }

async function getPerfil(env, uid) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}/usuarios/${uid}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return null;
  const d = await r.json();
  return readDoc(d.fields);
}
async function getInvitacion(env, jti) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}/invitaciones/${jti}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return null;
  return readDoc((await r.json()).fields);
}
async function firestoreSet(env, path, fields, atOverride) {
  const at = atOverride || await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const r = await fetch(`${fsBase(env)}/${path}`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!r.ok) throw httpErr(500, 'Firestore set falló');
}
async function firestoreUpdate(env, path, fields, mask) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const qs = mask.map(m=>`updateMask.fieldPaths=${m}`).join('&');
  await fetch(`${fsBase(env)}/${path}?${qs}`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
}
async function logApertura(env, o) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  await fetch(`${fsBase(env)}/aperturas`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields: {
      uid:{stringValue:o.uid}, nombre:{stringValue:o.nombre||'Usuario'},
      puerta:{stringValue:o.puerta}, hogar:{stringValue:o.hogar},
      tipo:{stringValue:o.tipo}, ts:{timestampValue:new Date().toISOString()},
    }}),
  });
}
async function notificarResidente(env, residenteUid, mensaje) {
  const perfil = await getPerfil(env, residenteUid);
  if (!perfil?.fcmToken) return;
  const at = await saToken(env, 'https://www.googleapis.com/auth/firebase.messaging');
  await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/messages:send`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ message:{ token: perfil.fcmToken,
      notification:{ title:'Cerrada Mixcoac', body: mensaje } } }),
  }).catch(()=>{});
}

/* Convierte fields Firestore → objeto plano (solo los tipos que usamos) */
function readDoc(fields) {
  if (!fields) return null;
  const o = {};
  for (const [k,v] of Object.entries(fields)) {
    if ('stringValue' in v) o[k]=v.stringValue;
    else if ('integerValue' in v) o[k]=+v.integerValue;
    else if ('doubleValue' in v) o[k]=+v.doubleValue;
    else if ('booleanValue' in v) o[k]=v.booleanValue;
    else if ('timestampValue' in v) o[k]=v.timestampValue;
    else if ('nullValue' in v) o[k]=null;
  }
  return o;
}

/* ===========================================================
   QR firmado (HMAC) + pre-sync al lector
   =========================================================== */
async function hmacKey(env){
  return crypto.subtle.importKey('raw', new TextEncoder().encode(env.QR_SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign','verify']);
}
async function signQR(env, obj){
  const body = b64url(JSON.stringify(obj));
  const k = await hmacKey(env);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(body));
  return `${body}.${bytesToB64url(new Uint8Array(sig))}`;
}
async function verifyQR(env, payload){
  const [body, sig] = (payload||'').split('.');
  if (!body || !sig) return null;
  const k = await hmacKey(env);
  const ok = await crypto.subtle.verify('HMAC', k, b64urlToBytes(sig), new TextEncoder().encode(body));
  if (!ok) return null;
  const obj = JSON.parse(b64urlToStr(body));
  if (obj.exp * 1000 < Date.now()) return null;
  return obj;
}
async function presyncReader(env, item){
  if (!env.READER_SYNC_URL) return;   // endpoint local del lector (cuando se defina el modelo)
  await fetch(env.READER_SYNC_URL, {
    method:'POST', headers:{ 'Content-Type':'application/json', 'X-Reader-Key': env.READER_KEY || '' },
    body: JSON.stringify(item),
  });
}

/* ===========================================================
   CRYPTO / BASE64 helpers
   =========================================================== */
function b64url(str){ return bytesToB64url(new TextEncoder().encode(str)); }
function bytesToB64url(bytes){
  let bin=''; for (const b of bytes) bin+=String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlToBytes(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='=';
  const bin=atob(s); const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out;
}
function b64urlToStr(s){ return new TextDecoder().decode(b64urlToBytes(s)); }

async function importX509(pem){
  const der = pemToDer(pem);
  // Extrae la clave pública del certificado X.509
  return crypto.subtle.importKey('spki', der, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify'])
    .catch(async ()=> {
      // Algunos runtimes requieren importar el cert completo; fallback a spki ya intentado.
      throw httpErr(500, 'No se pudo importar la clave de Google');
    });
}
async function importPKCS8(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey('pkcs8', der, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']);
}
function pemToDer(pem){
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  return b64urlToBytes(b64.replace(/\+/g,'-').replace(/\//g,'_'));
}

/* ===========================================================
   HTTP utils
   =========================================================== */
function json(obj, status=200){ return new Response(JSON.stringify(obj), { status, headers:{'Content-Type':'application/json'} }); }
function httpErr(status, msg){ const e=new Error(msg); e.status=status; return e; }
function cors(res, origin){
  const h = new Headers(res.headers);
  h.set('Access-Control-Allow-Origin', origin);
  h.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Firebase-AppCheck, X-Reader-Key');
  h.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  return new Response(res.body, { status:res.status, headers:h });
}
