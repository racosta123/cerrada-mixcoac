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

/* FASE 7 — esAdmin: un JEFE de familia (rol 'residente' sin jefeId) puede tener además
   esAdmin:true y ganar poderes de staff, conservando casa/cuota/voto/familiares. NO es una
   segunda cuenta ni un rol nuevo: es un permiso aditivo que SOLO el master prende/apaga
   (/personas/admin). El "modo" del front es cosmético; el permiso real se decide AQUÍ,
   releyendo el perfil de Firestore en cada petición.
   El check de estado va solo en la rama esAdmin: master/admin no se suspenden, pero un jefe
   SÍ (por mora) — y un jefe suspendido no debe conservar los poderes de admin. */
function esStaff(p) {
  if (!p) return false;
  if (STAFF.has(p.rol)) return true;
  return p.esAdmin === true && (p.estado || 'activo') === 'activo';
}
/* Vista de "persona del padrón" (no del perfil): a un staff solo lo toca el MASTER — un
   admin no suspende, reactiva ni edita a otro admin. */
function esStaffPersona(p) {
  return !!p && (p.rol === 'master' || p.rol === 'admin' || p.esAdmin === true);
}

export default {
  async fetch(req, env) {
    const reqOrigin = req.headers.get('Origin') || '';
    const allowed = new Set([env.ALLOWED_ORIGIN].filter(Boolean));
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
        case '/finanzas/cobranza': out = await cobranzaFinanzas(req, env); break;
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
        case '/personas/crear':     out = await crearPersona(req, env); break;
        case '/personas/actualizar': out = await actualizarPersona(req, env); break;
        case '/personas/suspender': out = await suspenderPersona(req, env); break;
        case '/personas/reactivar': out = await reactivarPersona(req, env); break;
        case '/personas/borrar':    out = await borrarPersona(req, env); break;
        case '/personas/admin':     out = await adminPersona(req, env); break;
        case '/personas/listar':    out = await listarPersonas(req, env); break;
        case '/personas/mis-familiares': out = await misFamiliares(req, env); break;
        case '/personas/familiar-cancelar': out = await cancelarFamiliar(req, env); break;
        case '/invitaciones/familiar': out = await crearInvitacionFamiliar(req, env); break;
        case '/votaciones/crear':         out = await crearVotacion(req, env); break;
        case '/votaciones/cerrar':        out = await cerrarVotacion(req, env); break;
        case '/votaciones/votar':         out = await votarVotacion(req, env); break;
        case '/votaciones/estado':        out = await estadoVotacion(req, env); break;
        case '/votaciones/participacion': out = await participacionVotacion(req, env); break;
        case '/votaciones/historial':     out = await historialVotaciones(req, env); break;
        case '/votaciones/participantes':  out = await participantesVotacion(req, env); break;
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
  if (!esStaff(perfil)) throw httpErr(403, 'No autorizado');

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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo master/admin registran finanzas');

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
    // FASE 6.5: la casa debe ser un JEFE de familia activo del padrón de personas.
    const jefes = (await personasList(env)).filter(p => esJefe(p) && (p.estado || 'activo') === 'activo');
    const match = jefes.find(j => j.domicilioNorm === domNorm);
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

  // FASE 7 — autocobro: un jefe-admin puede registrar el pago de SU PROPIA casa (es admin y
  // es casa a la vez). Es legítimo, pero no debe ser invisible: queda en la bitácora. Borrar
  // movimientos sigue siendo solo-master, así que no puede tapar su propio rastro.
  if (perfil.esAdmin === true && casaCanon && normDomicilio(perfil.casa || '') === normDomicilio(casaCanon)) {
    await logBitacora(env, await saToken(env, 'https://www.googleapis.com/auth/datastore'), {
      uid: user.uid,
      nombre: `${perfil.nombre || 'Admin'} registró un pago de su propia casa (${casaCanon}) por ${m}`,
    });
  }
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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo master/admin');

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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff da de alta vecinos');

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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff edita vecinos');

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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta el padrón');

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
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff genera invitaciones');

  const { personaId } = await req.json();
  if (!personaId || !/^[A-Za-z0-9-]{10,64}$/.test(personaId)) throw httpErr(400, 'personaId inválido');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const persona = byId[personaId];
  if (!persona) throw httpErr(404, 'Persona no existe');
  if ((persona.estado || 'activo') !== 'activo') throw httpErr(409, 'La persona no está activa');
  if (persona.uid) throw httpErr(409, 'Esta persona ya tiene una cuenta');
  if (persona.jefeId) throw httpErr(400, 'A un familiar lo invita su jefe, no staff');

  const t = await emitirInvitacion(env, at, { persona, byId, creadoPor: user.uid });
  return json({ ok:true, token: t.token, expiraEn: t.expiraEn });
}

/* /invitaciones/familiar — el JEFE (residente activo con cuenta) invita a un familiar.
   Crea la persona familiar (Sin cuenta, hereda domicilio del jefe) + token. ≤5 familiares
   vivos validado AQUÍ (server-side). Familiar y suspendido NO pueden invitar. */
async function crearInvitacionFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe) throw httpErr(403, 'Sin perfil');
  if (!esJefe(jefe)) throw httpErr(403, 'Solo un jefe de familia puede invitar familiares');
  if ((jefe.estado || 'activo') !== 'activo') throw httpErr(403, 'Tu cuenta está suspendida; no puedes invitar');

  const { nombre, telefono } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  if (!nom) throw httpErr(400, 'Falta el nombre del familiar');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');

  // Límite de 5 familiares VIVOS (los suspendidos ocupan slot).
  if (all.filter(p => p.jefeId === jefe.id).length >= 5) throw httpErr(409, 'Ya alcanzaste el máximo de 5 familiares');

  const fid = crypto.randomUUID();
  await firestoreSet(env, `personas/${fid}`, {
    nombre:{stringValue:nom},
    telefono:{stringValue:tel},
    correo:{nullValue:null},
    domicilio:{stringValue:''},          // familiar NO guarda domicilio: se DERIVA del jefe
    domicilioNorm:{stringValue:''},
    rol:{stringValue:'residente'},
    estado:{stringValue:'activo'},
    uid:{nullValue:null},
    jefeId:{stringValue:jefe.id},
    suspendidoPor:{nullValue:null},
    creadoPor:{stringValue:user.uid},
    creadoEn:{timestampValue:new Date().toISOString()},
  }, at);

  const persona = { id: fid, nombre: nom, jefeId: jefe.id, rol:'residente' };
  byId[fid] = persona;
  const t = await emitirInvitacion(env, at, { persona, byId, creadoPor: user.uid });
  return json({ ok:true, familiarId: fid, token: t.token, expiraEn: t.expiraEn });
}

/* Emite un token de un uso para una persona: invalida los previos no usados de esa persona
   (solo una viva a la vez) y guarda el hash + datos denormalizados (nombre + domicilio
   resuelto para mostrar). Devuelve el token en claro UNA sola vez. */
async function emitirInvitacion(env, at, { persona, byId, creadoPor }) {
  const previas = (await firestoreList(env, 'registro_invitaciones'))
    .filter(d => { const x = readDoc(d.fields); return x.personaId === persona.id && !x.usado; });
  for (const d of previas) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${d.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  }
  const token = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await sha256b64url(token);
  const expiraEn = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
  await firestoreSet(env, `registro_invitaciones/${hash}`, {
    hashToken:{stringValue:hash},
    personaId:{stringValue:persona.id},
    domicilio:{stringValue: domicilioDe(persona, byId)},
    nombre:{stringValue: persona.nombre || ''},
    creadoPor:{stringValue: creadoPor},
    creadoEn:{timestampValue:new Date().toISOString()},
    expiraEn:{timestampValue:expiraEn},
    usado:{booleanValue:false},
    usadoEn:{nullValue:null},
  }, at);
  return { token, expiraEn };
}

/* /personas/familiar-cancelar — el JEFE elimina a un familiar suyo que sigue "Sin cuenta"
   (invitado pero nunca registrado), liberando el slot; invalida sus invitaciones vivas. */
async function cancelarFamiliar(req, env) {
  const user = await requireAuth(req, env);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe || !esJefe(jefe)) throw httpErr(403, 'Solo un jefe puede cancelar a sus familiares');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const fam = all.find(p => p.id === id);
  if (!fam || fam.jefeId !== jefe.id) throw httpErr(404, 'Ese familiar no es tuyo');
  if (fam.uid) throw httpErr(409, 'Ese familiar ya tiene cuenta; no se puede cancelar aquí');

  for (const iv of (await firestoreList(env, 'registro_invitaciones')).filter(d => { const x = readDoc(d.fields); return x.personaId === id && !x.usado; })) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${iv.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(()=>{});
  }
  await fetch(`${fsBase(env)}/personas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  return json({ ok:true, id });
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

  // La persona debe seguir viva, activa y sin cuenta. rol/domicilio/jefeId salen del doc.
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const persona = byId[inv.x.personaId];
  if (!persona) throw httpErr(409, 'La invitación ya no es válida');
  if (persona.uid) throw httpErr(409, 'Esta persona ya tiene una cuenta');
  if ((persona.estado || 'activo') !== 'activo') throw httpErr(409, 'Esta persona está suspendida');

  // 1) QUEMA-PRIMERO con compare-and-set (precondición updateTime). 412 = otro ya lo quemó.
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

  // 2) Crear la cuenta de Auth (nombre del padrón). Si el correo ya existe, revertir.
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts`, {
    method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' },
    body: JSON.stringify({ email: correo, password: pass, displayName: persona.nombre || '', emailVerified:false }),
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

  // 3) Escribir correo+uid en la PERSONA (fuente de verdad) y sincronizar el índice
  //    usuarios/{uid} (rol/casa/estado desde el doc de la persona, jamás del payload).
  await firestoreActualizarCampos(env, `personas/${persona.id}`, { correo:{stringValue:correo}, uid:{stringValue:localId} }, 'Persona');
  byId[persona.id] = { ...persona, correo, uid: localId };
  await syncUsuarioIndex(env, at, byId[persona.id], byId);

  return json({ ok:true });
}

/* ===========================================================
   PERSONAS (FASE 6.5) — padrón unificado. personas/{personaId} (id random estable) es
   la FUENTE DE VERDAD; el Worker lee de ahí rol/estado/domicilio, nunca del payload.
   usuarios/{uid} se mantiene como índice de auth (para reglas, getPerfil y /abrir) y lo
   sincroniza el Worker. Jefe = residente sin jefeId (la CASA). Familiar = residente con
   jefeId (HEREDA el domicilio del jefe, no se guarda copia). Admin/master = sin domicilio.
   =========================================================== */

async function personasList(env, at) {
  at = at || await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const docs = await firestoreList(env, 'personas');
  return docs.map(d => ({ id: d.name.split('/').pop(), ...readDoc(d.fields) }));
}
/* domicilio efectivo: el familiar HEREDA el del jefe (derivado, no copiado). */
function domicilioDe(p, byId) {
  if (p.jefeId) { const j = byId[p.jefeId]; return j ? (j.domicilio || '') : ''; }
  return p.domicilio || '';
}
function esJefe(p) { return p.rol === 'residente' && !p.jefeId; }

/* Proyecta la persona a usuarios/{uid} (solo si tiene cuenta) para reglas/getPerfil/abrir.
   updateMask para NO borrar el fcmToken que escribe el cliente. */
async function syncUsuarioIndex(env, at, persona, byId) {
  if (!persona || !persona.uid) return;
  const fields = {
    nombre:{stringValue: persona.nombre || ''},
    rol:{stringValue: persona.rol || 'residente'},
    casa:{stringValue: domicilioDe(persona, byId)},
    estado:{stringValue: persona.estado || 'activo'},
    suspendido:{booleanValue: (persona.estado || 'activo') === 'suspendido'},
    personaId:{stringValue: persona.id},
    jefeId:{stringValue: persona.jefeId || ''},
    esAdmin:{booleanValue: persona.esAdmin === true},   // FASE 7: lo leen esStaff() y staff() de las reglas
  };
  if (persona.correo) fields.email = {stringValue: persona.correo};
  await firestoreUpdate(env, `usuarios/${persona.uid}`, fields, Object.keys(fields));
}
/* Reindexar una persona y (si cambió su domicilio) todos sus familiares registrados. */
async function resyncFamilia(env, at, personaId, incluirFamiliares) {
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  await syncUsuarioIndex(env, at, byId[personaId], byId);
  if (incluirFamiliares) {
    for (const f of all.filter(x => x.jefeId === personaId)) await syncUsuarioIndex(env, at, f, byId);
  }
}

/* /personas/crear — SOLO staff. Alta de jefe (residente) o admin. El familiar NO se crea
   aquí (lo invita su jefe). El correo NO se captura (lo pone la persona al registrarse). */
async function crearPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff da de alta personas');

  const { nombre, telefono, domicilio, rol } = await req.json();
  const nom = String(nombre || '').trim().slice(0, 80);
  const tel = String(telefono || '').trim().slice(0, 30);
  if (!nom) throw httpErr(400, 'Falta el nombre');
  if (!tel) throw httpErr(400, 'El teléfono es obligatorio');
  if (!['admin', 'residente'].includes(rol)) throw httpErr(400, 'Rol inválido (admin o residente)');
  if (rol === 'admin' && perfil.rol !== 'master') throw httpErr(403, 'Solo master crea administradores');

  let dom = '', domNorm = '';
  if (rol === 'residente') {
    dom = String(domicilio || '').trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'El domicilio es obligatorio para residentes');
    domNorm = normDomicilio(dom);
    // Anti-duplicados SOLO entre jefes de familia vivos.
    const jefes = (await personasList(env)).filter(p => esJefe(p));
    if (jefes.some(j => j.domicilioNorm === domNorm)) throw httpErr(409, `Ya existe una casa con el domicilio "${dom}"`);
  }

  const id = crypto.randomUUID();
  await firestoreSet(env, `personas/${id}`, {
    nombre:{stringValue:nom},
    telefono:{stringValue:tel},
    correo:{nullValue:null},
    domicilio:{stringValue:dom},
    domicilioNorm:{stringValue:domNorm},
    rol:{stringValue:rol},
    estado:{stringValue:'activo'},
    esAdmin:{booleanValue:false},        // FASE 7: solo el master lo prende, vía /personas/admin
    uid:{nullValue:null},
    jefeId:{nullValue:null},
    suspendidoPor:{nullValue:null},
    creadoPor:{stringValue:user.uid},
    creadoEn:{timestampValue:new Date().toISOString()},
  });
  return json({ ok:true, id });
}

/* /personas/actualizar — SOLO staff. Edita nombre/teléfono/domicilio. El familiar no
   tiene domicilio propio. Renombrar domicilio se BLOQUEA si la casa tiene pagos. */
async function actualizarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff edita personas');

  const { id, nombre, telefono, domicilio } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede editar a un administrador');

  const fields = {};
  if (nombre !== undefined) { const nom = String(nombre).trim().slice(0,80); if (!nom) throw httpErr(400,'El nombre no puede quedar vacío'); fields.nombre = {stringValue:nom}; }
  if (telefono !== undefined) { const tel = String(telefono).trim(); if (!tel) throw httpErr(400,'El teléfono es obligatorio'); fields.telefono = {stringValue:tel.slice(0,30)}; }
  let cambioDomicilio = false;
  if (domicilio !== undefined) {
    if (p.jefeId) throw httpErr(400, 'Un familiar hereda el domicilio del jefe; no se edita aparte');
    if (p.rol !== 'residente') throw httpErr(400, 'Solo los residentes (jefes) tienen domicilio');
    const dom = String(domicilio).trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!dom) throw httpErr(400, 'Falta el domicilio');
    const domNorm = normDomicilio(dom);
    if (domNorm !== p.domicilioNorm) {
      const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
      if (finanzas.some(m => m.casa && normDomicilio(m.casa) === p.domicilioNorm)) {
        throw httpErr(409, 'Esta casa tiene pagos registrados: no se puede renombrar el domicilio (rompería recibos y morosos). Solo se permite si no tiene pagos.');
      }
      if (all.some(x => esJefe(x) && x.id !== id && x.domicilioNorm === domNorm)) throw httpErr(409, `Ya existe otra casa con el domicilio "${dom}"`);
      fields.domicilio = {stringValue:dom}; fields.domicilioNorm = {stringValue:domNorm};
      cambioDomicilio = true;
    }
  }
  if (!Object.keys(fields).length) throw httpErr(400, 'Nada que actualizar');

  await firestoreActualizarCampos(env, `personas/${id}`, fields, 'Persona');
  await resyncFamilia(env, at, id, cambioDomicilio);   // si cambió domicilio, resync familiares
  return json({ ok:true, id });
}

/* /personas/suspender — SOLO staff. Suspender jefe hace CASCADA a sus familiares activos
   (suspendidoPor='cascada'). Suspender familiar es individual. Todo en el Worker. */
async function suspenderPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff suspende personas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (p.rol === 'master') throw httpErr(403, 'No se puede suspender un master');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede suspender a un administrador');

  await firestoreActualizarCampos(env, `personas/${id}`, { estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'individual'} }, 'Persona');
  if (esJefe(p)) {
    for (const f of all.filter(x => x.jefeId === id && x.estado === 'activo')) {
      await firestoreActualizarCampos(env, `personas/${f.id}`, { estado:{stringValue:'suspendido'}, suspendidoPor:{stringValue:'cascada'} }, 'Persona');
    }
  }
  await resyncFamilia(env, at, id, esJefe(p));
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} suspendió a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/reactivar — SOLO staff. Reactivar jefe reactiva SOLO los familiares con
   suspendidoPor='cascada'. No se puede reactivar un familiar si su jefe sigue suspendido. */
async function reactivarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff reactiva personas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (esStaffPersona(p) && perfil.rol !== 'master') throw httpErr(403, 'Solo master puede reactivar a un administrador');
  if (p.jefeId) {
    const jefe = byId[p.jefeId];
    if (jefe && jefe.estado === 'suspendido') throw httpErr(409, 'Reactiva primero al jefe de familia (la casa está suspendida).');
  }

  await firestoreActualizarCampos(env, `personas/${id}`, { estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null} }, 'Persona');
  if (esJefe(p)) {
    for (const f of all.filter(x => x.jefeId === id && x.estado === 'suspendido' && x.suspendidoPor === 'cascada')) {
      await firestoreActualizarCampos(env, `personas/${f.id}`, { estado:{stringValue:'activo'}, suspendidoPor:{nullValue:null} }, 'Persona');
    }
  }
  await resyncFamilia(env, at, id, esJefe(p));
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Staff'} reactivó a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/borrar — SOLO master. Bloquea si el jefe tiene familiares o pagos. Respalda a
   personas_borradas, borra la cuenta Auth + índice usuarios + invitaciones vivas, y registra. */
async function borrarPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master borra personas');

  const { id } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const byId = {}; all.forEach(x => byId[x.id] = x);
  const p = byId[id]; if (!p) throw httpErr(404, 'Persona no existe');
  if (p.rol === 'master') throw httpErr(403, 'No se puede borrar un master');

  if (esJefe(p)) {
    const nFam = all.filter(x => x.jefeId === id).length;
    if (nFam) throw httpErr(409, `Este jefe tiene ${nFam} familiar(es). Elimínalos primero.`);
    const finanzas = (await firestoreList(env, 'finanzas')).map(d => readDoc(d.fields));
    if (finanzas.some(m => m.casa && normDomicilio(m.casa) === p.domicilioNorm)) {
      throw httpErr(409, 'Esta casa tiene pagos registrados: solo puedes suspenderla, no borrarla.');
    }
  }

  const rGet = await fetch(`${fsBase(env)}/personas/${id}`, { headers:{ Authorization:'Bearer '+at } });
  const doc = rGet.ok ? await rGet.json() : null;
  await firestoreSet(env, `personas_borradas/${id}`, {
    ...(doc?.fields || {}),
    borradoPor:{stringValue:user.uid}, borradoNombre:{stringValue:perfil.nombre||''}, borradoTs:{timestampValue:new Date().toISOString()},
  }, at);

  if (p.uid) {
    await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/accounts:delete`, {
      method:'POST', headers:{ Authorization:'Bearer '+at, 'Content-Type':'application/json' }, body: JSON.stringify({ localId: p.uid }),
    }).catch(() => {});
    await fetch(`${fsBase(env)}/usuarios/${p.uid}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
  }
  for (const iv of (await firestoreList(env, 'registro_invitaciones')).filter(d => { const x = readDoc(d.fields); return x.personaId === id && !x.usado; })) {
    await fetch(`${fsBase(env)}/registro_invitaciones/${iv.name.split('/').pop()}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } }).catch(() => {});
  }
  await fetch(`${fsBase(env)}/personas/${id}`, { method:'DELETE', headers:{ Authorization:'Bearer '+at } });
  await logBitacora(env, at, { uid:user.uid, nombre: `${perfil.nombre || 'Master'} borró a ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}` });
  return json({ ok:true, id });
}

/* /personas/admin — SOLO MASTER. Prende/apaga esAdmin sobre un JEFE de familia. El check es
   perfil.rol === 'master' (NO esStaff): un admin —puro o jefe-admin— no puede otorgárselo a
   sí mismo ni a nadie más. Funciona aunque el jefe aún no tenga cuenta: syncUsuarioIndex
   proyecta el permiso cuando se registre. */
async function adminPersona(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!perfil || perfil.rol !== 'master') throw httpErr(403, 'Solo master otorga permisos de administrador');

  const { id, esAdmin } = await req.json();
  if (!id || !/^[A-Za-z0-9-]{10,64}$/.test(id)) throw httpErr(400, 'id inválido');
  if (typeof esAdmin !== 'boolean') throw httpErr(400, 'esAdmin debe ser true o false');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const all = await personasList(env, at);
  const p = all.find(x => x.id === id);
  if (!p) throw httpErr(404, 'Persona no existe');
  // Solo un jefe: bloquea familiares (heredan domicilio), admins puros (ya son staff) y master.
  if (!esJefe(p)) throw httpErr(400, 'Solo un jefe de familia puede ser administrador');

  await firestoreActualizarCampos(env, `personas/${id}`, { esAdmin:{booleanValue:esAdmin} }, 'Persona');
  await resyncFamilia(env, at, id, false);
  await logBitacora(env, at, {
    uid: user.uid,
    nombre: `${perfil.nombre || 'Master'} ${esAdmin ? 'nombró administrador a' : 'quitó el permiso de administrador a'} ${p.nombre}${p.domicilio ? ' ('+p.domicilio+')' : ''}`,
  });
  return json({ ok:true, id, esAdmin });
}

/* /personas/listar — SOLO staff. Devuelve todo el padrón con domicilio resuelto (familiar
   hereda el del jefe) + el conteo de CASAS ACTIVAS (jefes activos) para el termómetro. */
async function listarPersonas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta el padrón');

  const all = await personasList(env);
  const byId = {}; all.forEach(p => byId[p.id] = p);
  const personas = all.map(p => ({
    id: p.id, nombre: p.nombre || '', telefono: p.telefono || '', correo: p.correo ?? null,
    rol: p.rol || 'residente', estado: p.estado || 'activo', uid: p.uid ?? null,
    jefeId: p.jefeId ?? null, suspendidoPor: p.suspendidoPor ?? null,
    domicilio: domicilioDe(p, byId), domicilioNorm: p.domicilioNorm || '',
    registrado: !!p.uid,
    esAdmin: p.esAdmin === true,   // FASE 7: para la etiqueta y el botón de master en Gestión
  }));
  const casasActivas = all.filter(p => esJefe(p) && (p.estado || 'activo') === 'activo').length;
  return json({ personas, casasActivas });
}

/* /personas/mis-familiares — el JEFE lista SOLO a su propia familia (self-service:
   badge N/5, invitar, cancelar). Nunca expone otras casas ni al resto del padrón.
   Devuelve id/nombre/estado/registrado de cada familiar + el tope de 5. */
async function misFamiliares(req, env) {
  const user = await requireAuth(req, env);
  const all = await personasList(env);
  const jefe = all.find(p => p.uid === user.uid);
  if (!jefe || !esJefe(jefe)) throw httpErr(403, 'Solo un jefe de familia tiene familiares');
  const familiares = all.filter(p => p.jefeId === jefe.id)
    .map(f => ({
      id: f.id, nombre: f.nombre || '', telefono: f.telefono || '',
      estado: f.estado || 'activo', registrado: !!f.uid, suspendidoPor: f.suspendidoPor ?? null,
    }))
    .sort((a, b) => a.nombre.localeCompare(b.nombre, 'es'));
  return json({
    familiares, max: 5,
    domicilio: jefe.domicilio || '',
    puedeInvitar: (jefe.estado || 'activo') === 'activo',
  });
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

  // FASE 6.5 (corregido): el total es el # de JEFES de familia (una casa = un jefe),
  // ACTIVOS Y SUSPENDIDOS. Se revoca el criterio de FASE 5 de excluir suspendidos: si un
  // suspendido no cuenta en el denominador, el % de cobranza mentiría.
  const totalCasas = (await personasList(env)).filter(p => esJefe(p)).length;

  return json({
    ingreso, egreso, balance: ingreso - egreso,
    pagaron: pagaron.size,
    totalCasas,
  });
}

/* ============ /finanzas/cobranza — SOLO staff ============
   Dos listas de casas (JEFES de familia, ACTIVAS y SUSPENDIDAS) para cobrar sin adivinar:
   las que ya pagaron Cuota este mes y las que no. Cada casa lleva su domicilio, el nombre
   del jefe y si está suspendida (para etiquetarla). TODO el conteo se hace aquí, no en el
   cliente. Las suspendidas SÍ aparecen (suelen estarlo justo por mora). */
async function cobranzaFinanzas(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo staff consulta la cobranza');

  const now = new Date();
  const inicioMes = new Date(now.getFullYear(), now.getMonth(), 1);
  const finMes = new Date(now.getFullYear(), now.getMonth()+1, 1);

  // Domicilios que pagaron Cuota este mes (normalizados para casar con el padrón).
  const pagadas = new Set();
  for (const doc of await firestoreList(env, 'finanzas')) {
    const d = readDoc(doc.fields);
    const ts = new Date(d.ts);
    if (!(ts >= inicioMes && ts < finMes)) continue;
    if (d.tipo === 'ingreso' && d.categoria === 'Cuota' && d.casa) pagadas.add(normDomicilio(d.casa));
  }

  // TODAS las casas (jefes), activas y suspendidas.
  const casas = (await personasList(env)).filter(p => esJefe(p));
  const pagaron = [], sinPago = [];
  for (const c of casas) {
    const item = { domicilio: c.domicilio || '', nombre: c.nombre || '', suspendido: (c.estado || 'activo') === 'suspendido' };
    (pagadas.has(c.domicilioNorm) ? pagaron : sinPago).push(item);
  }
  const cmp = (a, b) => (a.domicilio || '').localeCompare(b.domicilio || '', 'es', { numeric: true });
  pagaron.sort(cmp); sinPago.sort(cmp);

  return json({ pagaron, sinPago, totalCasas: casas.length });
}

/* ============ /usuarios/crear — solo staff, vía Admin ============ */
async function crearUsuario(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'No autorizado');

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
/* ===========================================================
   VOTACIONES (FASE V2) — endpoints del Worker.
   Garantías (ver el bloque votaciones/control de firestore.rules y el diseño aprobado):
   - MASTER NO GESTIONA: crear/cerrar solo admin y jefe-admin (403 al master). No basta
     esStaff() porque incluye al master; se excluye explícitamente con puedeGestionarVot().
   - Solo el JEFE (con casa) vota; casaId se DERIVA del perfil verificado en Firestore.
   - Un voto por casa: el id del doc participacion/{casaKey} es el candado (transacción).
   - Anonimato: la liga casa->opción vive solo en _privado/voto__{casaKey} (read:false) y se
     borra al congelar; participacion NO guarda opción; conteo es agregado.
   - Bloque de 5 estricto: nunca se libera un bloque incompleto (ni al cerrar). Nombres en
     orden aleatorio, sin orden ni timestamps. Candados (bloque + 1/hora) SOLO en el Worker.
   - Hora de SERVIDOR (reloj del Worker) en todo; el dispositivo nunca decide.
   =========================================================== */
const HORA_MS = 3600 * 1000;
const UMBRAL_MIN = 5;   // mínimo de participantes para mostrar el marcador
const BLOQUE = 5;       // los nombres se liberan solo en bloques completos de 5

// Gestionar (crear/cerrar) = admin puro o jefe-admin ACTIVO. NUNCA master. staff() no basta.
function puedeGestionarVot(p) {
  if (!p || p.rol === 'master') return false;
  if (p.rol === 'admin') return true;
  return p.esAdmin === true && (p.estado || 'activo') === 'activo';
}
// Jefe = residente sin jefeId y con casa. Admin puro / master / familiar => NO votan.
function esJefePerfil(p) {
  return !!p && p.rol === 'residente' && !p.jefeId && !!(p.casa && String(p.casa).trim());
}
// Clave de doc estable y URL-safe por casa: hash del domicilio normalizado (sin espacios/acentos).
async function casaKeyDe(domicilio) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normDomicilio(domicilio)));
  return [...new Uint8Array(buf)].slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
}
function docName(env, path) { return `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents/${path}`; }
function mapaInts(obj) { const fields = {}; for (const [k, v] of Object.entries(obj)) fields[k] = { integerValue: String(v) }; return { mapValue: { fields } }; }
function arrOpciones(ops) { return { arrayValue: { values: ops.map(o => ({ mapValue: { fields: { id: { stringValue: o.id }, texto: { stringValue: o.texto } } } })) } }; }
function barajar(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

// GET simple (sin transacción). Devuelve el doc crudo {name,fields} o null.
async function getDoc(env, at, path) {
  const r = await fetch(`${fsBase(env)}/${path}`, { headers: { Authorization: 'Bearer ' + at } });
  if (r.status === 404) return null;
  if (!r.ok) throw httpErr(500, 'Firestore get falló');
  return r.json();
}
// Firestore -> objeto de votación, incluyendo opciones (array) y conteo (map), que readDoc no maneja.
function parseVotacion(doc) {
  if (!doc || !doc.fields) return null;
  const f = doc.fields;
  const base = readDoc(f) || {};
  base.opciones = (f.opciones?.arrayValue?.values || []).map(v => ({
    id: v.mapValue?.fields?.id?.stringValue, texto: v.mapValue?.fields?.texto?.stringValue,
  }));
  const cf = f.conteo?.mapValue?.fields;
  base.conteo = cf ? Object.fromEntries(Object.entries(cf).map(([k, v]) => [k, +(v.integerValue || 0)])) : null;
  base.id = doc.name.split('/').pop();
  return base;
}

// ---- transacción read-modify-write serializable (para doble voto y "una sola activa") ----
async function txBegin(env, at) {
  const r = await fetch(`${fsBase(env)}:beginTransaction`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ options: { readWrite: {} } }),
  });
  if (!r.ok) throw httpErr(500, 'No se pudo iniciar la transacción');
  return (await r.json()).transaction;
}
async function txGet(env, at, path, tx) {
  const r = await fetch(`${fsBase(env)}/${path}?transaction=${encodeURIComponent(tx)}`, { headers: { Authorization: 'Bearer ' + at } });
  if (r.status === 404) return null;
  if (!r.ok) throw httpErr(500, 'Firestore read (tx) falló');
  const d = await r.json();
  return d.fields ? d : null;
}
async function txCommit(env, at, tx, writes) {
  const r = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: tx, writes }),
  });
  return r.ok;   // false => conflicto (ABORTED): el caller reintenta
}
// Ejecuta fn(at, tx) -> { writes, value }; commitea con reintentos ante conflicto de concurrencia.
async function conTx(env, fn, tries = 4) {
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  for (let i = 0; i < tries; i++) {
    const tx = await txBegin(env, at);
    let out;
    try {
      out = await fn(at, tx);
    } catch (e) {
      await fetch(`${fsBase(env)}:rollback`, {
        method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
        body: JSON.stringify({ transaction: tx }),
      }).catch(() => {});
      throw e;   // error de negocio (403/409): no reintentar, propagar
    }
    if (await txCommit(env, at, tx, out.writes || [])) return out.value;
  }
  throw httpErr(409, 'Conflicto de concurrencia, reintenta');
}

// # de casas (jefes) activas del padrón — mismo criterio que /personas/listar.
async function contarCasasActivas(env, at) {
  const all = await personasList(env, at);
  return all.filter(p => esJefe(p) && (p.estado || 'activo') === 'activo').length;
}
// Borra la liga privada. soloVotos=true: solo voto__* (al congelar, conservando tally y throttles).
// soloVotos=false: TODO _privado (al cerrar). Best-effort, fuera de transacción.
async function borrarPrivado(env, at, votacionId, soloVotos) {
  let docs = [];
  try { docs = await firestoreList(env, `votaciones/${votacionId}/_privado`); } catch { return; }
  for (const d of docs) {
    const id = d.name.split('/').pop();
    if (soloVotos && !id.startsWith('voto__')) continue;
    await fetch(`${fsBase(env)}/votaciones/${votacionId}/_privado/${id}`, {
      method: 'DELETE', headers: { Authorization: 'Bearer ' + at },
    }).catch(() => {});
  }
}
// Reconciliación PEREZOSA del congelamiento (sin cron): en la 1a llamada tras congelaAt marca
// 'congelada' y BORRA la liga votante->opción. La liga es ilegible por cliente (read:false);
// solo la vería quien tenga la SA, y esta ventana la cierra el borrado. cerrar() borra el resto.
async function reconciliarFreeze(env, at, vot) {
  if (vot && vot.estado === 'abierta' && vot.congelaAt && Date.now() >= Date.parse(vot.congelaAt)) {
    await firestoreUpdate(env, `votaciones/${vot.id}`, { estado: { stringValue: 'congelada' } }, ['estado']);
    await borrarPrivado(env, at, vot.id, /* soloVotos */ true);
    vot.estado = 'congelada';
  }
  return vot;
}

/* ---- POST /votaciones/crear — admin o jefe-admin (403 al master) ---- */
async function crearVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!puedeGestionarVot(perfil)) throw httpErr(403, 'Solo un administrador puede crear votaciones');

  const body = await req.json();
  const titulo = String(body.titulo || '').trim();
  const descripcion = String(body.descripcion || '').trim();
  if (titulo.length < 3) throw httpErr(400, 'El título es muy corto');
  const textos = Array.isArray(body.opciones) ? body.opciones.map(s => String(s || '').trim()).filter(Boolean) : [];
  if (textos.length < 2 || textos.length > 10) throw httpErr(400, 'Se requieren entre 2 y 10 opciones');
  const cierra = Date.parse(body.cierraAt);
  if (!Number.isFinite(cierra)) throw httpErr(400, 'Fecha de cierre inválida');
  const ahora = Date.now();
  // Debe haber ventana de congelamiento: el cierre a más de 24h en el futuro (si no, congelaAt < ahora).
  if (cierra - ahora <= 24 * HORA_MS) throw httpErr(400, 'El cierre debe ser a más de 24h en el futuro (para la ventana de congelamiento)');
  const congela = cierra - 24 * HORA_MS;
  const umbral = Math.max(UMBRAL_MIN, +body.umbralConteo || UMBRAL_MIN);
  const opciones = textos.map((t, i) => ({ id: `op${i + 1}`, texto: t }));

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const totalCasas = await contarCasasActivas(env, at);
  const id = crypto.randomUUID();

  const votacionId = await conTx(env, async (atx, tx) => {
    const ctrl = await txGet(env, atx, 'control/votaciones', tx);
    const activaId = ctrl?.fields?.activaId?.stringValue || null;
    if (activaId) {
      const vdoc = await txGet(env, atx, `votaciones/${activaId}`, tx);
      const estado = vdoc?.fields?.estado?.stringValue;
      if (estado === 'abierta' || estado === 'congelada') throw httpErr(409, 'Ya hay una votación activa');
    }
    const fields = {
      titulo: { stringValue: titulo }, descripcion: { stringValue: descripcion },
      opciones: arrOpciones(opciones),
      estado: { stringValue: 'abierta' }, activa: { booleanValue: true },
      creadaPor: { stringValue: user.uid },
      createdAt: { timestampValue: new Date(ahora).toISOString() },
      cierraAt: { timestampValue: new Date(cierra).toISOString() },
      congelaAt: { timestampValue: new Date(congela).toISOString() },
      totalCasasSnapshot: { integerValue: String(totalCasas) },
      umbralConteo: { integerValue: String(umbral) },
      participaronCount: { integerValue: '0' },
      // sin campo "conteo" hasta que participaronCount >= umbral (umbral aplicado en datos)
    };
    return {
      writes: [
        { update: { name: docName(env, `votaciones/${id}`), fields }, currentDocument: { exists: false } },
        { update: { name: docName(env, 'control/votaciones'), fields: { activaId: { stringValue: id } } }, updateMask: { fieldPaths: ['activaId'] } },
      ],
      value: id,
    };
  });
  return json({ ok: true, votacionId });
}

/* ---- POST /votaciones/cerrar — admin o jefe-admin (403 al master) ---- */
async function cerrarVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!puedeGestionarVot(perfil)) throw httpErr(403, 'Solo un administrador puede cerrar votaciones');
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  if (vot.estado === 'cerrada') throw httpErr(409, 'La votación ya está cerrada');

  // FASE V2.5 — al cerrar, la votación queda como ACTA permanente. Fijamos el conteo final
  // desde _privado/tally (necesario si tuvo <umbral votos y el conteo público nunca se
  // publicó) y en el MISMO commit borramos TODO _privado, para que el acta jamás conserve
  // la liga votante->opción. Snapshot del AGREGADO (tally), nunca de voto__*.
  const privados = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []);
  const tally = {};
  const tf = privados.find(d => d.name.endsWith('/tally'))?.fields?.conteo?.mapValue?.fields;
  if (tf) for (const [k, v] of Object.entries(tf)) tally[k] = +(v.integerValue || 0);

  await conTx(env, async () => ({
    writes: [
      { update: { name: docName(env, `votaciones/${votacionId}`), fields: {
          estado: { stringValue: 'cerrada' }, activa: { booleanValue: false },
          conteo: mapaInts(tally),
          cerradaAt: { timestampValue: new Date().toISOString() },
          cerradaPor: { stringValue: user.uid },
        } }, updateMask: { fieldPaths: ['estado', 'activa', 'conteo', 'cerradaAt', 'cerradaPor'] } },
      { update: { name: docName(env, 'control/votaciones'), fields: { activaId: { nullValue: null } } }, updateMask: { fieldPaths: ['activaId'] } },
      ...privados.map(d => ({ delete: docName(env, `votaciones/${votacionId}/_privado/${d.name.split('/').pop()}`) })),
    ],
  }));

  // Defensa: ya cerrada, votar() rechaza nuevos votos, así que no aparecen más ligas. Si una se
  // coló entre el list y el commit, su voto__* no estaba en la lista borrada -> se limpia aquí,
  // de forma terminal. El acta NO se considera completa mientras _privado no quede VACÍO.
  let resto = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []);
  for (let i = 0; i < 3 && resto.length; i++) { await borrarPrivado(env, at, votacionId, false); resto = await firestoreList(env, `votaciones/${votacionId}/_privado`).catch(() => []); }
  if (resto.length) throw httpErr(500, 'No se pudo limpiar la liga privada al archivar');

  return json({ ok: true, votacionId, conteoFinal: tally, participaronCount: vot.participaronCount || 0 });
}

/* ---- POST /votaciones/historial — lista de votaciones CERRADAS (actas). Cualquier residente ----
   Solo el agregado + metadata; los nombres van en /votaciones/participantes. */
async function historialVotaciones(req, env) {
  await requireAuth(req, env);   // cualquier residente autenticado; sin sesión -> 401
  const docs = await firestoreList(env, 'votaciones');
  const cerradas = docs.map(parseVotacion).filter(v => v && v.estado === 'cerrada');
  cerradas.sort((a, b) => Date.parse(b.cerradaAt || b.cierraAt || 0) - Date.parse(a.cerradaAt || a.cierraAt || 0));
  const votaciones = cerradas.map(v => ({
    id: v.id, titulo: v.titulo, descripcion: v.descripcion, opciones: v.opciones,
    conteo: v.conteo || {}, participaronCount: v.participaronCount || 0,
    totalCasas: v.totalCasasSnapshot || 0, cerradaAt: v.cerradaAt || null, cierraAt: v.cierraAt || null,
  }));
  return json({ ok: true, votaciones });
}

/* ---- POST /votaciones/participantes — lista COMPLETA de una votación CERRADA. Cualquier residente ----
   Sin bloque de 5 ni throttle: la liga ya no existe y el marcador ya no se mueve, así que el
   bloque no protegería nada (es el acta). Sobre una votación ABIERTA -> 409 (usa /participacion). */
async function participantesVotacion(req, env) {
  await requireAuth(req, env);   // cualquier residente autenticado; sin sesión -> 401
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');
  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  if (vot.estado !== 'cerrada') throw httpErr(409, 'La lista completa solo está disponible en el historial (votaciones cerradas)');

  const docs = await firestoreList(env, `votaciones/${votacionId}/participacion`);
  const nombres = docs.map(d => readDoc(d.fields)).map(p => ({ nombre: p.nombre || '', casa: p.casa || '' }));
  nombres.sort((a, b) => (a.casa || '').localeCompare(b.casa || '', 'es', { numeric: true }));   // orden legible por casa (anonimato ya no depende del orden)
  return json({ ok: true, votacionId, titulo: vot.titulo, conteo: vot.conteo || {}, participaronCount: vot.participaronCount || 0, totalCasas: vot.totalCasasSnapshot || 0, nombres });
}

/* ---- POST /votaciones/votar — SOLO el jefe con casa (emitir o cambiar) ---- */
async function votarVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esJefePerfil(perfil)) throw httpErr(403, 'Solo el jefe de una casa puede votar');
  if (perfil.suspendido || (perfil.estado || 'activo') !== 'activo') throw httpErr(403, 'La casa está suspendida');
  const { opcion } = await req.json();
  if (!opcion || typeof opcion !== 'string') throw httpErr(400, 'Falta la opción');

  const casaKey = await casaKeyDe(perfil.casa);
  const casaDisplay = String(perfil.casa).trim().replace(/\s+/g, ' ');
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  const ctrl = await getDoc(env, at, 'control/votaciones');
  const activaId = ctrl?.fields?.activaId?.stringValue || null;
  if (!activaId) throw httpErr(409, 'No hay una votación activa');
  let vot = parseVotacion(await getDoc(env, at, `votaciones/${activaId}`));
  if (!vot) throw httpErr(409, 'No hay una votación activa');
  vot = await reconciliarFreeze(env, at, vot);   // congela + borra liga si ya pasó congelaAt

  const ahora = Date.now();
  if (vot.estado === 'cerrada' || ahora >= Date.parse(vot.cierraAt)) throw httpErr(409, 'La votación está cerrada');
  if (!vot.opciones.some(o => o.id === opcion)) throw httpErr(400, 'Opción inválida');
  const congelado = ahora >= Date.parse(vot.congelaAt);

  const value = await conTx(env, async (atx, tx) => {
    const part = await txGet(env, atx, `votaciones/${activaId}/participacion/${casaKey}`, tx);
    const votDoc = await txGet(env, atx, `votaciones/${activaId}`, tx);
    const tallyDoc = await txGet(env, atx, `votaciones/${activaId}/_privado/tally`, tx);
    const participaron = +(votDoc?.fields?.participaronCount?.integerValue || 0);
    const umbral = +(votDoc?.fields?.umbralConteo?.integerValue || UMBRAL_MIN);
    const tally = {};
    const tf = tallyDoc?.fields?.conteo?.mapValue?.fields;
    if (tf) for (const [k, v] of Object.entries(tf)) tally[k] = +(v.integerValue || 0);

    const writes = [];
    let nuevoParticiparon = participaron;

    if (part) {
      // CAMBIO — bloqueado si ya se congeló.
      if (congelado) throw httpErr(409, 'El voto ya está congelado: a 24h del cierre no se puede cambiar');
      const votoPrev = await txGet(env, atx, `votaciones/${activaId}/_privado/voto__${casaKey}`, tx);
      const prev = votoPrev?.fields?.opcionActual?.stringValue;
      if (prev && prev !== opcion) {
        tally[prev] = Math.max(0, (tally[prev] || 0) - 1);
        tally[opcion] = (tally[opcion] || 0) + 1;
      }
      writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/voto__${casaKey}`), fields: { opcionActual: { stringValue: opcion } } }, updateMask: { fieldPaths: ['opcionActual'] } });
    } else {
      // PRIMERA VEZ — el id del doc participacion/{casaKey} es el candado anti-doble-voto.
      nuevoParticiparon = participaron + 1;
      tally[opcion] = (tally[opcion] || 0) + 1;
      writes.push({ update: { name: docName(env, `votaciones/${activaId}/participacion/${casaKey}`), fields: { orden: { integerValue: String(nuevoParticiparon) }, nombre: { stringValue: perfil.nombre || '' }, casa: { stringValue: casaDisplay } } }, currentDocument: { exists: false } });
      // liga privada SOLO mientras se pueda cambiar (pre-freeze); post-freeze no se guarda liga alguna.
      if (!congelado) writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/voto__${casaKey}`), fields: { opcionActual: { stringValue: opcion } } } });
    }
    // tally interno (Worker-only) siempre al día.
    writes.push({ update: { name: docName(env, `votaciones/${activaId}/_privado/tally`), fields: { conteo: mapaInts(tally) } }, updateMask: { fieldPaths: ['conteo'] } });
    // doc público: participaronCount + espejo de conteo SOLO si se alcanzó el umbral.
    const votUpdate = { participaronCount: { integerValue: String(nuevoParticiparon) } };
    const mask = ['participaronCount'];
    if (nuevoParticiparon >= umbral) { votUpdate.conteo = mapaInts(tally); mask.push('conteo'); }
    writes.push({ update: { name: docName(env, `votaciones/${activaId}`), fields: votUpdate }, updateMask: { fieldPaths: mask } });

    return { writes, value: { yaVotaste: true, miOpcionActual: opcion, puedeCambiar: !congelado } };
  });
  return json({ ok: true, ...value });
}

/* ---- POST /votaciones/estado — cualquier vecino: marcador en vivo + si YO ya voté ---- */
async function estadoVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  const ctrl = await getDoc(env, at, 'control/votaciones');
  const activaId = ctrl?.fields?.activaId?.stringValue || null;
  if (!activaId) return json({ activa: null });
  let vot = parseVotacion(await getDoc(env, at, `votaciones/${activaId}`));
  if (!vot) return json({ activa: null });
  vot = await reconciliarFreeze(env, at, vot);

  const ahora = Date.now();
  const cerrada = vot.estado === 'cerrada' || ahora >= Date.parse(vot.cierraAt);
  const congelado = ahora >= Date.parse(vot.congelaAt);

  const resp = {
    activa: {
      id: vot.id, titulo: vot.titulo, descripcion: vot.descripcion, opciones: vot.opciones,
      estado: cerrada ? 'cerrada' : (congelado ? 'congelada' : 'abierta'),
      cierraAt: vot.cierraAt, congelaAt: vot.congelaAt,
      participaronCount: vot.participaronCount || 0, totalCasas: vot.totalCasasSnapshot || 0,
      umbralConteo: vot.umbralConteo || UMBRAL_MIN,
      conteo: vot.conteo || null,          // solo presente si participaronCount >= umbral
      conteoOculto: !vot.conteo,
    },
  };
  // Vista PERSONAL del jefe (solo su propia casa). Nadie ve la opción de nadie más.
  if (esJefePerfil(perfil)) {
    const casaKey = await casaKeyDe(perfil.casa);
    const part = await getDoc(env, at, `votaciones/${activaId}/participacion/${casaKey}`);
    const yaVotaste = !!part;
    let miOpcionActual = null;
    if (yaVotaste && !congelado) {
      const voto = await getDoc(env, at, `votaciones/${activaId}/_privado/voto__${casaKey}`);
      miOpcionActual = voto?.fields?.opcionActual?.stringValue || null;
    }
    resp.yo = { esJefe: true, yaVotaste, miOpcionActual, puedeCambiar: yaVotaste && !congelado && !cerrada };
  } else {
    resp.yo = { esJefe: false };   // admin puro / master / familiar no votan
  }
  return json(resp);
}

/* ---- POST /votaciones/participacion — lista nominal, con los DOS candados en el Worker ----
   Lectura permitida a staff (master incluido: master LEE todo, no gestiona). Jefe/familiar => 403.
   Candado 1: bloque de 5 estricto (nunca un bloque incompleto). Candado 2: 1 consulta/hora por
   cuenta, con hora de servidor. Ambos aquí; manipular el front no los burla (recibe 403). */
async function participacionVotacion(req, env) {
  const user = await requireAuth(req, env);
  const perfil = await getPerfil(env, user.uid);
  if (!esStaff(perfil)) throw httpErr(403, 'Solo el staff consulta la lista de participación');
  const { votacionId } = await req.json();
  if (!votacionId || typeof votacionId !== 'string') throw httpErr(400, 'Falta votacionId');

  const at = await saToken(env, 'https://www.googleapis.com/auth/datastore');

  // Candado 2 — 1/hora por cuenta (hora de servidor), bucket independiente por uid.
  const accPath = `votaciones/${votacionId}/_privado/admin__${user.uid}`;
  const acc = await getDoc(env, at, accPath);
  const ultimo = acc?.fields?.ultimoAccesoAt?.timestampValue ? Date.parse(acc.fields.ultimoAccesoAt.timestampValue) : 0;
  if (Date.now() - ultimo < HORA_MS) throw httpErr(403, 'Solo puedes consultar la lista una vez por hora');
  await firestoreSet(env, accPath, { ultimoAccesoAt: { timestampValue: new Date().toISOString() } }, at);

  const vot = parseVotacion(await getDoc(env, at, `votaciones/${votacionId}`));
  if (!vot) throw httpErr(404, 'Votación no encontrada');
  const participaron = vot.participaronCount || 0;
  // Candado 1 — bloque de 5 estricto: solo bloques COMPLETOS, nunca el remanente (ni al cerrar).
  const reveladosCount = Math.floor(participaron / BLOQUE) * BLOQUE;

  let nombres = [];
  if (reveladosCount > 0) {
    const docs = await firestoreList(env, `votaciones/${votacionId}/participacion`);
    nombres = docs.map(d => readDoc(d.fields))
      .filter(p => (p.orden || 0) <= reveladosCount)
      .map(p => ({ nombre: p.nombre || '', casa: p.casa || '' }));   // sin orden, sin timestamps
    barajar(nombres);   // orden aleatorio dentro del bloque
  }
  return json({ ok: true, participaronCount: participaron, reveladosCount, pendientesSinDesglosar: participaron - reveladosCount, nombres });
}

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
