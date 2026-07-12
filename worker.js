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

// Cada acceso es un Shelly físico independiente, controlado por Shelly Cloud (internet).
// IDs reales PENDIENTES hasta elegir/instalar el hardware — no inventar valores.
const DEVICES = {
  residentes: "PENDIENTE_residentes",  // barrera vehicular de residentes
  visitantes: "PENDIENTE_visitantes",  // barrera vehicular de visitas/morosos
  peatones:   "PENDIENTE_peatones",    // puerta peatonal
  salida:     "PENDIENTE_salida",      // puerta de salida
};
const STAFF = new Set(['master','admin']);

// SOLO DESARROLLO: permite probar el Worker desde el servidor local de pruebas.
// Quitar esta línea cuando ya no se necesite probar desde localhost.
const DEV_ORIGINS = ['http://localhost:4173'];

export default {
  async fetch(req, env) {
    const reqOrigin = req.headers.get('Origin') || '';
    const allowed = new Set([env.ALLOWED_ORIGIN, ...DEV_ORIGINS].filter(Boolean));
    const origin = allowed.has(reqOrigin) ? reqOrigin : (env.ALLOWED_ORIGIN || '*');
    if (req.method === 'OPTIONS') return cors(new Response(null,{status:204}), origin);

    const url = new URL(req.url);
    try {
      let out;
      switch (url.pathname) {
        case '/abrir':             out = await abrir(req, env); break;
        case '/invitacion/crear':  out = await crearInvitacion(req, env); break;
        case '/validar-qr':        out = await validarQR(req, env); break;  // lo llama el lector físico
        case '/finanzas/registrar': out = await registrarFinanza(req, env); break;
        case '/finanzas/resumen':  out = await resumenFinanzas(req, env); break;
        case '/finanzas/marcar-recibo': out = await marcarRecibo(req, env); break;
        case '/finanzas/borrar':   out = await borrarFinanza(req, env); break;
        case '/vecinos/crear':     out = await crearVecino(req, env); break;
        case '/vecinos/actualizar': out = await actualizarVecino(req, env); break;
        case '/vecinos/borrar':    out = await borrarVecino(req, env); break;
        case '/vecinos/listar':    out = await listarVecinos(req, env); break;
        case '/invitaciones/crear':    out = await crearInvitacionRegistro(req, env); break;
        case '/invitaciones/validar':  out = await validarInvitacionRegistro(req, env); break;
        case '/invitaciones/completar': out = await completarInvitacionRegistro(req, env); break;
        case '/usuarios/crear':    out = await crearUsuario(req, env); break;
        case '/usuarios/suspender': out = await suspenderUsuario(req, env); break;
        case '/usuarios/borrar':   out = await borrarUsuario(req, env); break;
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
  if (!(puerta in DEVICES)) throw httpErr(400, 'Puerta no válida');

  const perfil = await getPerfil(env, user.uid);
  if (!perfil) throw httpErr(403, 'Sin perfil');
  // Un residente suspendido (por mora) no puede abrir; tampoco sus esclavos.
  if (perfil.suspendido) throw httpErr(403, 'Residente suspendido por mora');
  if (perfil.rol === 'esclavo' && perfil.residenteUid) {
    const padre = await getPerfil(env, perfil.residenteUid);
    if (padre && padre.suspendido) throw httpErr(403, 'Residente del hogar suspendido por mora');
  }
  // master, admin, residente y esclavo pueden abrir las 4 puertas.
  await triggerShelly(env, DEVICES[puerta]);

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

  await triggerShelly(env, DEVICES.visitantes);
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

/* ============ /usuarios/borrar — SOLO master ============
   Borra la cuenta de Firebase Auth + su doc /usuarios, y limpia el uid del vecino
   vinculado (uid→null) para que se pueda reinvitar. Respaldo a usuarios_borrados y
   registro en bitácora. No permite borrarse a sí mismo ni a otra cuenta master. */
async function borrarUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra cuentas');

  const { uid } = await req.json();
  if (!uid || typeof uid !== 'string' || uid.length < 6 || uid.length > 128) throw httpErr(400, 'uid inválido');
  if (uid === user.uid) throw httpErr(409, 'No puedes borrar tu propia cuenta');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');

  // Snapshot del doc /usuarios para el respaldo.
  const rGet = await fetch(`${fsBase(env)}/usuarios/${uid}`, { headers:{ Authorization:'Bearer '+at } });
  const usuarioDoc = rGet.ok ? await rGet.json() : null;
  const objetivo = usuarioDoc ? readDoc(usuarioDoc.fields) : {};
  if (objetivo.rol === 'master') throw httpErr(403, 'No se puede borrar una cuenta master');

  // Respaldo (quién/cuándo/snapshot completo).
  await firestoreSet(env, `usuarios_borrados/${uid}`, {
    ...(usuarioDoc?.fields || {}),
    borradoPor:{stringValue:user.uid},
    borradoNombre:{stringValue:perfil.nombre||''},
    borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  // Borra la cuenta de Firebase Auth. Si ya no existe (USER_NOT_FOUND), sigue limpiando.
  const rDel = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts:delete`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ localId: uid }),
  });
  if (!rDel.ok) {
    const err = await rDel.json().catch(() => ({}));
    if (!String(err.error?.message || '').includes('USER_NOT_FOUND')) throw httpErr(500, 'No se pudo borrar la cuenta de Auth');
  }

  // Borra el doc /usuarios/{uid}.
  await fetch(`${fsBase(env)}/usuarios/${uid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});

  // Limpia el uid del vecino vinculado (→ null) para poder reinvitar ese domicilio.
  let domicilioLiberado = null;
  const vinc = (await firestoreList(env, 'vecinos')).find(d => readDoc(d.fields).uid === uid);
  if (vinc) {
    const vid = vinc.name.split('/').pop();
    domicilioLiberado = readDoc(vinc.fields).domicilio || null;
    await firestoreActualizarCampos(env, `vecinos/${vid}`, { uid:{nullValue:null} }, 'Vecino');
  }

  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} borró la cuenta de ${objetivo.nombre || objetivo.email || uid}`,
  });

  return json({ ok:true, uid, domicilioLiberado });
}

// Trim + colapsa espacios dobles/múltiples a uno solo (no prohíbe espacios internos,
// solo normaliza — así "casa  57" y "casa 57" terminan guardados igual).
/* ============ /finanzas/registrar — solo master/admin ============ */
async function registrarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo master/admin registran finanzas');

  const { tipo, concepto, categoria, monto, casa } = await req.json();
  if (!['ingreso','egreso'].includes(tipo)) throw httpErr(400, 'Tipo inválido');
  const m = Number(monto);
  if (!concepto || !(m > 0)) throw httpErr(400, 'Concepto o monto inválido');

  const cat = String(categoria||'Otro').slice(0,40);

  // FASE 5: en ingresos, casa DEBE coincidir con el domicilio de un vecino ACTIVO del
  // padrón (comparación normalizada; NO se confía en el frontend). Se guarda el domicilio
  // canónico del padrón para que morosos/termómetro/consulta casen exacto.
  let casaCanon = '';
  if (tipo === 'ingreso') {
    const dom = String(casa == null ? '' : casa).trim().replace(/\s+/g, ' ');
    if (!dom) throw httpErr(400, 'Falta el domicilio para un ingreso');
    const domNorm = normDomicilio(dom);
    const vecinos = (await firestoreList(env, 'vecinos')).map(d => readDoc(d.fields));
    const match = vecinos.find(v => v.domicilioNorm === domNorm && (v.estado || 'activo') === 'activo');
    if (!match) throw httpErr(400, `Domicilio no registrado o suspendido: "${dom}"`);
    casaCanon = match.domicilio;
  }

  // Los ingresos llevan recibo: folio consecutivo del mes, asignado de forma atómica.
  // Se asigna DESPUÉS de validar la casa para no quemar un folio en un registro inválido.
  const folioRecibo = tipo === 'ingreso' ? await siguienteFolioRecibo(env) : '';

  const id = crypto.randomUUID();
  await firestoreSet(env, `finanzas/${id}`, {
    tipo:{stringValue:tipo},
    concepto:{stringValue:String(concepto).slice(0,120)},
    categoria:{stringValue:cat},
    monto:{doubleValue:m},
    casa:{stringValue:casaCanon},
    ...(folioRecibo ? { folioRecibo:{stringValue:folioRecibo} } : {}),
    creadoPor:{stringValue:user.uid},
    creadoNombre:{stringValue:perfil.nombre||''},
    ts:{timestampValue:new Date().toISOString()},
  });
  return json({ ok:true, id, folioRecibo });
}

/* folio consecutivo atómico REC-YYYYMM-### — un solo commit con updateTransforms
   (increment) sobre config/folios: Firestore aplica el +1 de forma atómica y
   devuelve el valor resultante en transformResults, sin transacción explícita ni
   carreras entre registros simultáneos. El contador reinicia cada mes (campo
   rec_YYYYMM nuevo). config/folios está bajo match /config → solo el Worker escribe. */
async function siguienteFolioRecibo(env) {
  const now = new Date();
  const ym = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}`;
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)`;
  const r = await fetch(`https://firestore.googleapis.com/v1/${base}/documents:commit`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({
      writes: [{
        // update con máscara vacía = merge que crea el doc si no existe;
        // el increment va aparte en updateTransforms.
        update: { name: `${base}/documents/config/folios`, fields: {} },
        updateMask: { fieldPaths: [] },
        updateTransforms: [{ fieldPath: `rec_${ym}`, increment: { integerValue: '1' } }],
      }],
    }),
  });
  if (!r.ok) throw httpErr(500, 'No se pudo asignar folio');
  const d = await r.json();
  const n = Number(d.writeResults?.[0]?.transformResults?.[0]?.integerValue);
  if (!Number.isInteger(n) || n <= 0) throw httpErr(500, 'No se pudo asignar folio');
  return `REC-${ym}-${String(n).padStart(3,'0')}`;
}

/* ============ /finanzas/marcar-recibo — solo master/admin ============
   Marca en el movimiento cuándo se compartió o descargó su recibo, para que el
   reporte por casa pueda referenciar "enviado el ...". Solo toca ese campo. */
async function marcarRecibo(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo master/admin');

  const { id, accion } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  if (!['compartido','descargado'].includes(accion)) throw httpErr(400, 'accion inválida');

  const campo = accion === 'compartido' ? 'reciboCompartidoTs' : 'reciboDescargadoTs';
  await firestoreActualizarCampos(env, `finanzas/${id}`, {
    [campo]:{timestampValue:new Date().toISOString()},
  }, 'Movimiento');
  return json({ ok:true, id, [campo]: true });
}

/* ============ /finanzas/borrar — SOLO master ============
   Para errores de captura y pruebas. Antes de borrar copia el documento completo a
   finanzas_borrados/{id} con quién y cuándo (auditoría; sin match en las reglas →
   ilegible para clientes, visible solo en la consola de Firebase / vía Worker). */
async function borrarFinanza(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra movimientos');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const rGet = await fetch(`${fsBase(env)}/finanzas/${id}`, { headers:{ Authorization:'Bearer '+at } });
  if (rGet.status === 404) throw httpErr(404, 'Movimiento no existe');
  if (!rGet.ok) throw httpErr(500, 'Firestore get falló');
  const docActual = await rGet.json();

  await firestoreSet(env, `finanzas_borrados/${id}`, {
    ...(docActual.fields || {}),
    borradoPor:{stringValue:user.uid},
    borradoNombre:{stringValue:perfil.nombre||''},
    borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  const rDel = await fetch(`${fsBase(env)}/finanzas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  if (!rDel.ok) throw httpErr(500, 'Firestore delete falló');
  return json({ ok:true, id });
}

/* ===========================================================
   VECINOS (padrón) — FASE 5, solo staff
   Padrón de jefes de familia. El domicilio es la fuente de verdad de las "casas"
   en Finanzas. Campos uid/miembros quedan reservados para FASE 6 (vínculo con
   cuentas de login); aquí solo se inicializan, no se usan.
   El cliente NUNCA lee vecinos directo: lo hace vía /vecinos/listar (sin match en
   las reglas = denegado por default), así no hubo que tocar firestore.rules.
   =========================================================== */

/* Normaliza el domicilio SOLO para comparar unicidad: trim + colapsar espacios +
   MAYÚSCULAS. Así "Ajoya 12", "ajoya 12" y "AJOYA  12" son la misma casa. */
function normDomicilio(s) {
  return String(s || '').trim().replace(/\s+/g, ' ').toUpperCase();
}

async function crearVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo staff da de alta vecinos');

  const { nombre, correo, telefono, domicilio } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  const dom = String(domicilio || '').trim().replace(/\s+/g, ' ').slice(0, 80);
  const cor = String(correo || '').trim().slice(0, 120);
  if (!nom) throw httpErr(400, 'Falta el nombre del vecino');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
  if (!dom) throw httpErr(400, 'Falta el domicilio');
  const domNorm = normDomicilio(dom);

  // Anti-duplicados server-side: el domicilio normalizado no debe existir aún.
  const existentes = (await firestoreList(env, 'vecinos')).map(d => readDoc(d.fields));
  if (existentes.some(v => v.domicilioNorm === domNorm)) {
    throw httpErr(409, `Ya existe un vecino con el domicilio "${dom}"`);
  }

  const id = crypto.randomUUID();
  await firestoreSet(env, `vecinos/${id}`, {
    nombre:{stringValue:nom},
    correo:{stringValue:cor},
    telefono:{stringValue:tel},
    domicilio:{stringValue:dom},
    domicilioNorm:{stringValue:domNorm},
    estado:{stringValue:'activo'},
    uid:{nullValue:null},                    // reservado FASE 6
    miembros:{arrayValue:{values:[]}},       // reservado FASE 6
    creadoPor:{stringValue:user.uid},
    creadoNombre:{stringValue:perfil.nombre||''},
    ts:{timestampValue:new Date().toISOString()},
  });
  return json({ ok:true, id });
}

async function actualizarVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo staff edita vecinos');

  const { id, nombre, correo, telefono, domicilio, estado } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');

  const fields = {};
  if (nombre !== undefined) {
    const nom = String(nombre).trim().slice(0, 80);
    if (!nom) throw httpErr(400, 'El nombre no puede quedar vacío');
    fields.nombre = {stringValue:nom};
  }
  if (correo !== undefined) fields.correo = {stringValue:String(correo).trim().slice(0,120)};
  if (telefono !== undefined) {
    const tel = String(telefono).trim();
    if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
    fields.telefono = {stringValue:tel.slice(0,30)};
  }
  if (estado !== undefined) {
    if (!['activo','suspendido'].includes(estado)) throw httpErr(400, 'estado inválido');
    fields.estado = {stringValue:estado};
  }
  if (domicilio !== undefined) {
    const dom = String(domicilio).trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'Falta el domicilio');
    const domNorm = normDomicilio(dom);
    const existentes = await firestoreList(env, 'vecinos');
    const dup = existentes.some(d => d.name.split('/').pop() !== id && readDoc(d.fields).domicilioNorm === domNorm);
    if (dup) throw httpErr(409, `Ya existe otro vecino con el domicilio "${dom}"`);
    fields.domicilio = {stringValue:dom};
    fields.domicilioNorm = {stringValue:domNorm};
  }
  if (!Object.keys(fields).length) throw httpErr(400, 'Nada que actualizar');

  await firestoreActualizarCampos(env, `vecinos/${id}`, fields, 'Vecino');
  return json({ ok:true, id });
}

async function listarVecinos(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo staff consulta el padrón');

  const docs = await firestoreList(env, 'vecinos');
  const vecinos = docs.map(d => {
    const x = readDoc(d.fields);
    return {
      id: d.name.split('/').pop(),
      nombre: x.nombre || '',
      correo: x.correo || '',
      telefono: x.telefono || '',
      domicilio: x.domicilio || '',
      domicilioNorm: x.domicilioNorm || '',
      estado: x.estado || 'activo',
      uid: x.uid ?? null,          // reservado FASE 6
    };
  });
  // El conteo de activos se calcula AQUÍ (server-side) y es el que usa el termómetro:
  // el frontend no lo deriva por su cuenta (no se confía en el cliente).
  const activos = vecinos.filter(v => v.estado === 'activo').length;
  return json({ vecinos, activos });
}

/* ============ /vecinos/borrar — SOLO master ============
   Baja del padrón con respaldo (mismo patrón que finanzas/borrar). Reglas:
   - Solo master (validado aquí, no se confía en el frontend).
   - Bloquea si el vecino tiene pagos en finanzas → evita recibos huérfanos; en ese
     caso solo se permite editar/suspender.
   - Copia el doc completo a vecinos_borrados (quién/cuándo/snapshot) y lo elimina de
     "vecinos", con lo que el domicilio se LIBERA para el anti-dup (que solo compara
     contra vecinos vivos, nunca contra borrados).
   - Deja registro en la bitácora. */
async function borrarVecino(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra vecinos');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const rGet = await fetch(`${fsBase(env)}/vecinos/${id}`, { headers:{ Authorization:'Bearer '+at } });
  if (rGet.status === 404) throw httpErr(404, 'Vecino no existe');
  if (!rGet.ok) throw httpErr(500, 'Firestore get falló');
  const docActual = await rGet.json();
  const vecino = readDoc(docActual.fields);
  const domNorm = vecino.domicilioNorm || normDomicilio(vecino.domicilio || '');

  // Bloqueo por pagos: si existe algún movimiento de finanzas de este domicilio, no se
  // borra (los recibos quedarían huérfanos). Solo editar/suspender.
  const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
  const tienePagos = finanzas.some(m => m.casa && normDomicilio(m.casa) === domNorm);
  if (tienePagos) {
    throw httpErr(409, 'Este vecino tiene pagos registrados: solo puedes editarlo o suspenderlo, no borrarlo');
  }

  await firestoreSet(env, `vecinos_borrados/${id}`, {
    ...(docActual.fields || {}),
    borradoPor:{stringValue:user.uid},
    borradoNombre:{stringValue:perfil.nombre||''},
    borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  const rDel = await fetch(`${fsBase(env)}/vecinos/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  if (!rDel.ok) throw httpErr(500, 'Firestore delete falló');

  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} borró al vecino ${vecino.domicilio || id}`,
  });

  return json({ ok:true, id });
}

/* Registro de acción administrativa en la bitácora (colección aperturas). tipo:'gestion'
   la distingue de aperturas de puertas; hogar = uid del staff que actúa, así los
   residentes (que filtran su bitácora por hogar) no la ven — solo staff. */
async function logBitacora(env, at, { uid, nombre }) {
  await fetch(`${fsBase(env)}/aperturas`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields: {
      uid:{stringValue:uid},
      nombre:{stringValue:nombre},
      puerta:{stringValue:'gestion'},
      hogar:{stringValue:uid},
      tipo:{stringValue:'gestion'},
      ts:{timestampValue:new Date().toISOString()},
    }}),
  });
}

/* ===========================================================
   INVITACIONES DE REGISTRO (FASE 6) — vincular vecino → cuenta de login
   Colección registro_invitaciones/{hashToken} (SEPARADA de los QR de visita, que
   viven en /invitaciones). El token en claro NUNCA se guarda ni se genera en el
   frontend: solo su hash SHA-256, que además es el id del doc → lookup O(1) por hash,
   sin enumerar. El token viaja solo en el fragmento del link.
   =========================================================== */

async function sha256b64url(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToB64url(new Uint8Array(digest));
}
/* Igualdad en tiempo constante: no corta en el primer byte distinto. */
function timingSafeEqual(a, b) {
  const ba = new TextEncoder().encode(a), bb = new TextEncoder().encode(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

/* Lee y valida una invitación por su token. Devuelve { x, updateTime, hash } o null.
   Validación POR HASH y en tiempo constante — nunca por igualdad del token en claro. */
async function leerInvitacionValida(env, at, token) {
  const hash = await sha256b64url(String(token || ''));
  const r = await fetch(`${fsBase(env)}/registro_invitaciones/${hash}`, { headers:{ Authorization:'Bearer '+at } });
  if (!r.ok) return null;
  const doc = await r.json();
  const x = readDoc(doc.fields);
  if (!x || !timingSafeEqual(x.hashToken || '', hash)) return null;
  if (x.usado) return null;
  if (!x.expiraEn || new Date(x.expiraEn) < new Date()) return null;
  return { x, updateTime: doc.updateTime, hash };
}

/* /invitaciones/crear — SOLO staff. Token de un uso para que un vecino ACTIVO y SIN
   cuenta se registre. Invalida invitaciones previas no usadas del mismo vecino (solo
   una viva a la vez). Devuelve el token en claro UNA sola vez. */
async function crearInvitacionRegistro(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || !STAFF.has(perfil.rol)) throw httpErr(403, 'Solo staff genera invitaciones');

  const { vecinoId } = await req.json();
  if (!vecinoId || !/^[A-Za-z0-9-]{10,64}$/.test(vecinoId)) throw httpErr(400, 'vecinoId inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const rGet = await fetch(`${fsBase(env)}/vecinos/${vecinoId}`, { headers:{ Authorization:'Bearer '+at } });
  if (rGet.status === 404) throw httpErr(404, 'Vecino no existe');
  if (!rGet.ok) throw httpErr(500, 'Firestore get falló');
  const vecino = readDoc((await rGet.json()).fields);
  if ((vecino.estado || 'activo') !== 'activo') throw httpErr(409, 'El vecino no está activo');
  if (vecino.uid) throw httpErr(409, 'El vecino ya tiene una cuenta vinculada');

  // Solo una invitación viva a la vez: borra las previas no usadas de este vecino.
  const previas = (await firestoreList(env, 'registro_invitaciones'))
    .filter(d => { const x = readDoc(d.fields); return x.vecinoId === vecinoId && !x.usado; });
  for (const d of previas) {
    const pid = d.name.split('/').pop();
    await fetch(`${fsBase(env)}/registro_invitaciones/${pid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  }

  // Token aleatorio de 32 bytes (256 bits). Solo su hash se persiste (como id del doc).
  const token = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await sha256b64url(token);
  const expiraEn = new Date(Date.now() + 72 * 3600 * 1000).toISOString();

  await firestoreSet(env, `registro_invitaciones/${hash}`, {
    hashToken:{stringValue:hash},
    vecinoId:{stringValue:vecinoId},
    domicilio:{stringValue:vecino.domicilio || ''},
    nombre:{stringValue:vecino.nombre || ''},
    creadoPor:{stringValue:user.uid},
    creadoEn:{timestampValue:new Date().toISOString()},
    expiraEn:{timestampValue:expiraEn},
    usado:{booleanValue:false},
    usadoEn:{nullValue:null},
  }, at);

  return json({ ok:true, token, expiraEn });
}

/* /invitaciones/validar — PÚBLICO (token-gated). Solo revela nombre + domicilio.
   Error genérico si no sirve (sin decir si fue inexistente/usada/vencida). */
async function validarInvitacionRegistro(req, env) {
  const { token } = await req.json();
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const inv = await leerInvitacionValida(env, at, token);
  if (!inv) throw httpErr(400, 'Invitación inválida o expirada');
  return json({ ok:true, nombre: inv.x.nombre || '', domicilio: inv.x.domicilio || '' });
}

/* /invitaciones/completar — PÚBLICO. Crea la cuenta del residente. QUEMA-PRIMERO:
   CAS atómico usado:false→true por precondición de updateTime; si gana la carrera crea
   la cuenta y escribe el uid; si la creación falla (p.ej. correo ya existe) revierte el
   token a usado:false. rol/casa/nombre los pone el Worker desde el doc del vecino —
   NUNCA del payload del cliente. */
async function completarInvitacionRegistro(req, env) {
  const { token, email, password } = await req.json();
  const correo = String(email || '').trim();
  const pass = String(password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) throw httpErr(400, 'Correo inválido');
  if (pass.length < 8) throw httpErr(400, 'La contraseña debe tener al menos 8 caracteres');

  const at = await saToken(env, 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore');
  const inv = await leerInvitacionValida(env, at, token);
  if (!inv) throw httpErr(400, 'Invitación inválida o expirada');

  // 1) QUEMA-PRIMERO con compare-and-set (precondición updateTime). Un 412 = otro request
  //    ya lo quemó en la carrera → un solo uso garantizado.
  const burnUrl = `${fsBase(env)}/registro_invitaciones/${inv.hash}`
    + `?updateMask.fieldPaths=usado&updateMask.fieldPaths=usadoEn`
    + `&currentDocument.updateTime=${encodeURIComponent(inv.updateTime)}`;
  const rBurn = await fetch(burnUrl, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields:{ usado:{booleanValue:true}, usadoEn:{timestampValue:new Date().toISOString()} } }),
  });
  if (rBurn.status === 412 || rBurn.status === 409) throw httpErr(409, 'Esta invitación ya fue usada');
  if (!rBurn.ok) throw httpErr(500, 'No se pudo procesar la invitación');

  const revertirQuemado = async () => {
    await fetch(`${fsBase(env)}/registro_invitaciones/${inv.hash}?updateMask.fieldPaths=usado&updateMask.fieldPaths=usadoEn`, {
      method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
      body: JSON.stringify({ fields:{ usado:{booleanValue:false}, usadoEn:{nullValue:null} } }),
    }).catch(()=>{});
  };

  // 2) Crear la cuenta de Auth. Si el correo ya existe, se revierte el quemado (no se
  //    consume el token) y se avisa claro.
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ email: correo, password: pass, displayName: inv.x.nombre || '', emailVerified:false }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    await revertirQuemado();
    if (String(err.error?.message || '').startsWith('EMAIL_EXISTS')) {
      throw httpErr(409, 'Ese correo ya está registrado. Usa otro o inicia sesión con él.');
    }
    throw httpErr(400, 'No se pudo crear la cuenta');
  }
  const { localId } = await res.json();

  // 3) Perfil de login (rol/casa desde el vecino) + vínculo uid en el doc del vecino.
  await firestoreSet(env, `usuarios/${localId}`, {
    nombre:{stringValue: inv.x.nombre || ''},
    email:{stringValue: correo},
    rol:{stringValue:'residente'},
    casa:{stringValue: inv.x.domicilio || ''},
  }, at);
  await firestoreActualizarCampos(env, `vecinos/${inv.x.vecinoId}`, { uid:{stringValue:localId} }, 'Vecino');

  return json({ ok:true });
}

/* ============ /finanzas/resumen — cualquier usuario autenticado ============
   Devuelve SOLO agregados del mes en curso (cobrado, gastos, balance, y el
   termómetro X de Y casas pagaron) — nunca el detalle de movimientos ni qué
   casa específica pagó. Así el dashboard de residentes no necesita leer
   "finanzas" directo (las reglas de Firestore ya se lo bloquean). */
async function resumenFinanzas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil) throw httpErr(403, 'Sin perfil');

  const now = new Date();
  const inicioMes = new Date(now.getFullYear(), now.getMonth(), 1);
  const finMes = new Date(now.getFullYear(), now.getMonth()+1, 1);

  const docs = await firestoreList(env, 'finanzas');
  let ingreso = 0, egreso = 0;
  const pagaron = new Set();
  for (const doc of docs) {
    const d = readDoc(doc.fields);
    const ts = new Date(d.ts);
    if (!(ts >= inicioMes && ts < finMes)) continue;
    if (d.tipo === 'ingreso') ingreso += d.monto || 0;
    else if (d.tipo === 'egreso') egreso += d.monto || 0;
    if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa) pagaron.add(d.casa);
  }

  // FASE 5: el total es el # de vecinos ACTIVOS del padrón (ya no config.totalCasas).
  const vecinos = (await firestoreList(env, 'vecinos')).map(d => readDoc(d.fields));
  const totalCasas = vecinos.filter(v => (v.estado || 'activo') === 'activo').length;

  return json({
    ingreso, egreso, balance: ingreso - egreso,
    pagaron: pagaron.size,
    totalCasas,
  });
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
async function triggerShelly(env, deviceId) {
  // Shelly CLOUD Control API (por internet, no IP local).
  // Cada acceso es un dispositivo Shelly propio (deviceId), no un canal compartido.
  // Un solo "turn=on": igual que antes, sin apagado explícito desde el Worker —
  // el pulso lo maneja el auto-off configurado en el propio Shelly.
  const body = new URLSearchParams({
    id: deviceId,
    channel: '0',
    turn: 'on',
    auth_key: env.SHELLY_AUTH_KEY,
  });
  const r = await fetch(`${env.SHELLY_HOST}/device/relay/control`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
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
/* Lista completa de una colección (paginada) — usada por /finanzas/resumen y vecinos. */
async function firestoreList(env, coleccion) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const docs = [];
  let pageToken;
  do {
    const url = new URL(`${fsBase(env)}/${coleccion}`);
    url.searchParams.set('pageSize', '300');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const r = await fetch(url, { headers:{ Authorization:'Bearer '+at } });
    if (!r.ok) throw httpErr(500, 'Firestore list falló');
    const d = await r.json();
    (d.documents||[]).forEach(doc => docs.push(doc));
    pageToken = d.nextPageToken;
  } while (pageToken);
  return docs;
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
/* Como firestoreUpdate pero estricto: máscara derivada de los campos, exige que el
   documento exista (no crea fantasmas si el id es inválido) y truena con error claro. */
async function firestoreActualizarCampos(env, path, fields, label = 'Documento') {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const qs = Object.keys(fields).map(f=>`updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
  const r = await fetch(`${fsBase(env)}/${path}?${qs}&currentDocument.exists=true`, {
    method:'PATCH', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (r.status === 404 || r.status === 400) throw httpErr(404, `${label} no existe`);
  if (!r.ok) throw httpErr(500, 'Firestore update falló');
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

// Lee un TLV DER en `offset`: soporta longitud corta y larga (suficiente para certs X.509).
function derReadTLV(bytes, offset){
  const tag = bytes[offset];
  const lenByte = bytes[offset+1];
  let length, lenOffset = offset+2;
  if (lenByte & 0x80){
    const numBytes = lenByte & 0x7f;
    length = 0;
    for (let i=0;i<numBytes;i++) length = (length<<8) | bytes[lenOffset+i];
    lenOffset += numBytes;
  } else {
    length = lenByte;
  }
  return { tag, contentStart: lenOffset, totalLen: (lenOffset-offset)+length };
}
// Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sig }
// tbsCertificate ::= SEQUENCE { [0] version?, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
// El SPKI que necesita crypto.subtle.importKey('spki', ...) está anidado ahí adentro, hay que extraerlo.
function extractSpkiFromX509(der){
  const cert = derReadTLV(der, 0);
  const tbs = derReadTLV(der, cert.contentStart);
  let p = tbs.contentStart;
  let el = derReadTLV(der, p);
  if (el.tag === 0xA0) p += el.totalLen; // version [0] EXPLICIT, opcional
  for (let i=0; i<5; i++){ el = derReadTLV(der, p); p += el.totalLen; } // serialNumber, signature, issuer, validity, subject
  el = derReadTLV(der, p); // subjectPublicKeyInfo
  return der.slice(p, p + el.totalLen);
}
async function importX509(pem){
  const der = pemToDer(pem);
  try {
    const spki = extractSpkiFromX509(der);
    return await crypto.subtle.importKey('spki', spki, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
  } catch (e) {
    throw httpErr(500, 'No se pudo importar la clave de Google');
  }
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
