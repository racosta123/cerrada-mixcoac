/* ===========================================================
   Cerrada Mixcoac · app.js
   Stack: Firebase (Auth+Firestore+FCM+AppCheck) + Cloudflare Worker + Shelly
   SEGURIDAD: el cliente NUNCA toca la Shelly ni guarda llaves.
   Toda apertura pasa por el Worker, que valida el ID token de Firebase.
   =========================================================== */

/* ---- Init Firebase ---- */
firebase.initializeApp(CONFIG.firebase);
const auth = firebase.auth();
const db   = firebase.firestore();

/* App Check (reCAPTCHA v3) — protege Firestore y el Worker de abuso */
if (CONFIG.appCheckSiteKey) {
  firebase.appCheck().activate(CONFIG.appCheckSiteKey, true);
}

const WORKER = CONFIG.workerUrl;        // ej. https://mixcoac-proxy.acosta4770.workers.dev
const DOORS = [
  { id:'visitantes', name:'Visitantes', sub:'Acceso de invitados' },
  { id:'residentes', name:'Residentes', sub:'Entrada principal' },
  { id:'salida',     name:'Salida',     sub:'Barrera de salida' },
  { id:'peatones',   name:'Peatones',   sub:'Puerta peatonal' },
];

let ME = null;          // { uid, nombre, rol, casa, residenteUid? }
let unsubLog = null;
let unsubInvites = null;
let unsubFin = null;
let vecinosCache = [];        // padrón (FASE 5): fuente de verdad de las casas en Finanzas
let vecinosActivosCount = 0;  // conteo de activos calculado por el Worker (denominador del termómetro)

/* ====================== UTILIDADES ====================== */
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

function toast(msg, kind){
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (kind ? ' '+kind : '');
  clearTimeout(t._t);
  t._t = setTimeout(()=> t.className='toast', 2600);
}

async function authedFetch(path, body){
  const token = await auth.currentUser.getIdToken();
  const headers = { 'Content-Type':'application/json', 'Authorization':'Bearer '+token };
  // App Check token (si está activo) para el Worker
  try {
    if (firebase.appCheck && CONFIG.appCheckSiteKey){
      const ac = await firebase.appCheck().getToken();
      if (ac?.token) headers['X-Firebase-AppCheck'] = ac.token;
    }
  } catch(e){}
  const res = await fetch(WORKER + path, { method:'POST', headers, body: JSON.stringify(body||{}) });
  if (!res.ok){
    let m = 'Error '+res.status;
    try { m = (await res.json()).error || m; } catch(e){}
    throw new Error(m);
  }
  return res.json().catch(()=> ({}));
}

/* ====================== LOGIN ====================== */
$('#loginBtn').addEventListener('click', doLogin);
$('#password').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });

async function doLogin(){
  const btn = $('#loginBtn');
  const email = $('#email').value.trim();
  const pass  = $('#password').value;
  $('#loginErr').textContent = '';
  if (!email || !pass){ $('#loginErr').textContent = 'Completa correo y contraseña'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await auth.signInWithEmailAndPassword(email, pass);
  } catch(e){
    $('#loginErr').textContent = mapAuthError(e.code);
    btn.disabled = false; btn.textContent = 'Entrar';
  }
}

function mapAuthError(code){
  const m = {
    'auth/invalid-credential':'Correo o contraseña incorrectos',
    'auth/invalid-email':'Correo no válido',
    'auth/user-disabled':'Usuario deshabilitado',
    'auth/too-many-requests':'Demasiados intentos. Espera un momento.',
  };
  return m[code] || 'No se pudo iniciar sesión';
}

$('#logoutBtn').addEventListener('click', ()=> auth.signOut());

/* ====================== SESIÓN ====================== */
auth.onAuthStateChanged(async user => {
  if (!user){ showLogin(); return; }
  try {
    const snap = await db.collection('usuarios').doc(user.uid).get();
    if (!snap.exists){
      toast('Tu cuenta no tiene perfil asignado', 'bad');
      await auth.signOut(); return;
    }
    ME = { uid:user.uid, ...snap.data() };
    enterApp();
  } catch(e){
    toast('Error cargando perfil', 'bad');
    await auth.signOut();
  }
});

function showLogin(){
  $('#appView').classList.add('hidden');
  $('#loginView').classList.remove('hidden');
  $('#password').value = '';
  $('#loginBtn').disabled = false; $('#loginBtn').textContent = 'Entrar';
  if (unsubLog) unsubLog();
  if (unsubInvites) unsubInvites();
  if (unsubFin) unsubFin();
}

function enterApp(){
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#avatar').textContent = (ME.nombre||'?').trim()[0].toUpperCase();
  $('#userName').textContent = ME.nombre || '—';
  $('#userRole').textContent = roleLabel(ME.rol) + (ME.casa ? ' · '+ME.casa : '');
  buildTabs();
  renderDoors();
  watchLog();
  watchFinanzas();
  if (ME.rol==='residente' || ME.rol==='esclavo') watchInvites();
  registerPush();
}

function roleLabel(r){
  return { master:'Master', admin:'Administrador', residente:'Residente', esclavo:'Invitado' }[r] || r;
}

/* ====================== TABS ====================== */
function buildTabs(){
  const isStaff = (ME.rol==='master' || ME.rol==='admin');
  const tabs = [
    { id:'doors',   label:'Puertas', icon:'M4 10h16v11H4z M8 10V7a4 4 0 0 1 8 0v3' },
  ];
  if (ME.rol==='residente' || ME.rol==='esclavo')
    tabs.push({ id:'invites', label:'Invitar', icon:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M19 8v6 M22 11h-6' });
  tabs.push({ id:'log', label: isStaff?'Bitácora':'Historial', icon:'M9 11l3 3L22 4 M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11' });
  tabs.push({ id:'finanzas', label:'Finanzas', icon:'M12 1v22 M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6' });
  if (isStaff)
    tabs.push({ id:'admin', label:'Gestión', icon:'M12 2a3 3 0 0 1 3 3v1m-6 0V5a3 3 0 0 1 3-3 M4 9h16v11H4z' });

  const bar = $('#tabbar'); bar.innerHTML = '';
  tabs.forEach((t,i) => {
    const b = document.createElement('button');
    b.className = 'tab' + (i===0?' active':'');
    b.dataset.tab = t.id;
    b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${t.icon}"/></svg><span>${t.label}</span>`;
    b.onclick = ()=> switchTab(t.id, b);
    bar.appendChild(b);
  });
  if (isStaff){ loadUsers(); loadVecinos(); }
}

function switchTab(id, btn){
  $$('.tabpane').forEach(p => p.classList.add('hidden'));
  $('#tab-'+id).classList.remove('hidden');
  $$('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  if (id === 'finanzas') resizeFinCharts();
}

/* ====================== PUERTAS ====================== */
function renderDoors(){
  const grid = $('#doorsGrid'); grid.innerHTML = '';
  // El invitado (visitante con QR) no usa esta app; los esclavos sí abren las 4.
  DOORS.forEach(d => {
    const el = document.createElement('div');
    el.className = 'door';
    el.innerHTML = `
      <div class="pulse"></div>
      <div class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="9" width="16" height="12" rx="2"/><path d="M8 9V6a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.4"/></svg></div>
      <div class="dn">${d.name}</div>
      <div class="ds">${d.sub}</div>`;
    el.onclick = ()=> openDoor(d, el);
    grid.appendChild(el);
  });
}

let opening = false;
async function openDoor(door, el){
  if (opening) return;
  opening = true; el.classList.add('opening');
  try {
    await authedFetch('/abrir', { puerta: door.id });
    toast(door.name + ' abriéndose', 'ok');
  } catch(e){
    toast(e.message || 'No se pudo abrir', 'bad');
  } finally {
    setTimeout(()=>{ el.classList.remove('opening'); opening=false; }, 1400);
  }
}

/* ====================== BITÁCORA / HISTORIAL ====================== */
function watchLog(){
  if (unsubLog) unsubLog();
  const isStaff = (ME.rol==='master' || ME.rol==='admin');
  let q = db.collection('aperturas').orderBy('ts','desc').limit(60);
  if (!isStaff){
    // residente ve lo suyo + sus esclavos/visitantes; esclavo ve lo suyo
    const scope = ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid);
    q = db.collection('aperturas').where('hogar','==',scope).orderBy('ts','desc').limit(60);
  }
  $('#logTitle').textContent = isStaff ? 'Bitácora general' : 'Historial';
  unsubLog = q.onSnapshot(snap => renderLog(snap), err => {
    console.error(err); $('#logList').innerHTML = '<div class="empty">Sin acceso al historial</div>';
  });
}

function renderLog(snap){
  const list = $('#logList');
  if (snap.empty){ list.innerHTML = '<div class="empty">Sin movimientos</div>'; return; }
  list.innerHTML = '';
  snap.forEach(doc => {
    const a = doc.data();
    const row = document.createElement('div');
    row.className = 'row';
    if (a.tipo === 'gestion'){
      // Acción administrativa (FASE 5), no una apertura de puerta: ícono de engrane,
      // el texto ya describe la acción, sin etiqueta Entrada/Salida.
      row.innerHTML = `
        <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></div>
        <div class="rt"><div class="a">${esc(a.nombre || 'Gestión')}</div><div class="b">Gestión · ${fmtTime(a.ts)}</div></div>
        <span class="tag">Gestión</span>`;
      list.appendChild(row); return;
    }
    const sentido = a.puerta==='salida' ? 'out' : 'in';
    row.innerHTML = `
      <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="9" width="16" height="12" rx="2"/><path d="M8 9V6a4 4 0 0 1 8 0v3"/></svg></div>
      <div class="rt"><div class="a">${esc(a.nombre || 'Usuario')}</div><div class="b">${puertaName(a.puerta)} · ${fmtTime(a.ts)}${a.tipo==='qr' ? ' · QR' : ''}</div></div>
      <span class="tag ${sentido}">${sentido==='out'?'Salida':'Entrada'}</span>`;
    list.appendChild(row);
  });
}

function puertaName(id){ return (DOORS.find(d=>d.id===id)||{}).name || id; }
function fmtTime(ts){
  if (!ts) return '';
  const d = ts.toDate ? ts.toDate() : new Date(ts);
  return d.toLocaleString('es-MX', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
}
function esc(s){ return (s||'').replace(/[<>&]/g, c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c])); }

/* ====================== INVITACIONES (QR visitante) ====================== */
let inviteDur = 4, inviteUses = 1;

$('#newInviteBtn').addEventListener('click', openInviteSheet);
$('#durSeg').addEventListener('click', e => segPick(e, '#durSeg', v => inviteDur = +v, 'h'));
$('#usesSeg').addEventListener('click', e => segPick(e, '#usesSeg', v => inviteUses = +v, 'u'));
$('#genInviteBtn').addEventListener('click', generateInvite);
$('#inviteOverlay').addEventListener('click', e => { if(e.target.id==='inviteOverlay') closeSheet('#inviteOverlay'); });

function segPick(e, sel, set, attr){
  const b = e.target.closest('button'); if(!b) return;
  $$(sel+' button').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); set(b.dataset[attr]);
}

function openInviteSheet(){
  $('#inviteForm').classList.remove('hidden');
  $('#inviteResult').classList.add('hidden');
  $('#visitorName').value = '';
  openSheet('#inviteOverlay');
}

async function generateInvite(){
  const name = $('#visitorName').value.trim();
  if (!name){ toast('Escribe el nombre del visitante', 'bad'); return; }
  const btn = $('#genInviteBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El Worker crea la invitación: genera token único, la guarda en Firestore,
    // y la PRE-SINCRONIZA al lector QR físico (resiliencia offline).
    const r = await authedFetch('/invitacion/crear', {
      visitante: name,
      horas: inviteDur,
      usos: inviteUses,          // 0 = ilimitado dentro de la vigencia
      hogar: ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid),
    });
    // r.payload = string que va dentro del QR (firmado por el Worker)
    const dataUrl = await QRCode.toDataURL(r.payload, { margin:1, width:460, errorCorrectionLevel:'M' });
    $('#qrImg').src = dataUrl;
    $('#qrMeta').textContent = `${name} · válido ${inviteDur} h`;
    $('#qrCount').textContent = inviteUses===0 ? 'Usos ilimitados durante la vigencia' : `${inviteUses} ${inviteUses===1?'uso':'usos'} · solo puerta de visitantes`;
    $('#inviteForm').classList.add('hidden');
    $('#inviteResult').classList.remove('hidden');
    $('#shareQrBtn').onclick = ()=> shareQR(dataUrl, name);
  } catch(e){
    toast(e.message || 'No se pudo generar', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = 'Generar código QR';
  }
}

async function shareQR(dataUrl, name){
  try {
    const blob = await (await fetch(dataUrl)).blob();
    const file = new File([blob], 'acceso-mixcoac.png', { type:'image/png' });
    if (navigator.canShare && navigator.canShare({ files:[file] })){
      await navigator.share({ files:[file], title:'Acceso Cerrada Mixcoac', text:`Código de acceso para ${name}` });
    } else {
      const a = document.createElement('a'); a.href = dataUrl; a.download = 'acceso-mixcoac.png'; a.click();
    }
  } catch(e){}
}

function watchInvites(){
  if (unsubInvites) unsubInvites();
  const hogar = ME.rol==='residente' ? ME.uid : (ME.residenteUid || ME.uid);
  unsubInvites = db.collection('invitaciones')
    .where('hogar','==',hogar).where('activa','==',true)
    .orderBy('expira','desc').limit(20)
    .onSnapshot(snap => {
      const list = $('#invitesList');
      if (snap.empty){ list.innerHTML = '<div class="empty">Sin invitaciones activas</div>'; return; }
      list.innerHTML = '';
      snap.forEach(doc => {
        const v = doc.data();
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = `
          <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z M21 14v.01 M21 21v.01 M17 21h.01"/></svg></div>
          <div class="rt"><div class="a">${esc(v.visitante)}</div><div class="b">Expira ${fmtTime(v.expira)} · ${v.usosRestantes==null?'∞':v.usosRestantes} restantes</div></div>
          <span class="tag">Activa</span>`;
        list.appendChild(row);
      });
    }, err => console.error(err));
}

/* ====================== ADMIN: usuarios ====================== */
let newRole = 'residente';
$('#newUserBtn')?.addEventListener('click', ()=> openSheet('#userOverlay'));
$('#userOverlay')?.addEventListener('click', e => { if(e.target.id==='userOverlay') closeSheet('#userOverlay'); });
$('#roleSeg')?.addEventListener('click', e => {
  const b = e.target.closest('button'); if(!b) return;
  $$('#roleSeg button').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); newRole = b.dataset.r;
  $('#casaField').style.display = newRole==='residente' ? 'block':'none';
});
$('#createUserBtn')?.addEventListener('click', createUser);

async function createUser(){
  const nombre = $('#nuName').value.trim();
  const email  = $('#nuEmail').value.trim();
  const pass   = $('#nuPass').value;
  const casa   = $('#nuCasa').value.trim();
  $('#nuErr').textContent = '';
  if (!nombre || !email || pass.length < 8){ $('#nuErr').textContent = 'Datos incompletos (contraseña ≥ 8)'; return; }
  if (newRole==='residente' && !casa){ $('#nuErr').textContent = 'Indica la casa / lote'; return; }
  const btn = $('#createUserBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El alta de cuentas la hace el Worker con Admin SDK (no se expone el registro público).
    await authedFetch('/usuarios/crear', { nombre, email, password:pass, rol:newRole, casa });
    toast('Usuario creado', 'ok');
    closeSheet('#userOverlay');
    $('#nuName').value=$('#nuEmail').value=$('#nuPass').value=$('#nuCasa').value='';
    loadUsers();
  } catch(e){
    $('#nuErr').textContent = e.message || 'No se pudo crear';
  } finally {
    btn.disabled = false; btn.textContent = 'Crear usuario';
  }
}

async function loadUsers(){
  try {
    const snap = await db.collection('usuarios').orderBy('rol').limit(200).get();
    const list = $('#usersList'); list.innerHTML = '';
    if (snap.empty){ list.innerHTML = '<div class="empty">Sin usuarios</div>'; return; }
    const usuariosById = {};
    snap.forEach(doc => {
      if (doc.id === ME.uid) return;
      const u = doc.data();
      usuariosById[doc.id] = { nombre: u.nombre||'', email: u.email||'', casa: u.casa||'', rol: u.rol };
      const row = document.createElement('div'); row.className = 'row';
      // Solo residentes se pueden suspender por mora. master no puede suspender admin.
      const puedeSuspender = u.rol==='residente' && !(ME.rol==='admin' && u.rol==='admin');
      let right;
      if (u.suspendido){
        right = `<span class="tag susp">Suspendido</span><button class="row-act" data-react="${doc.id}">Reactivar</button>`;
      } else if (puedeSuspender){
        right = `<span class="tag">${roleLabel(u.rol)}</span><button class="row-act danger" data-susp="${doc.id}">Suspender</button>`;
      } else {
        right = `<span class="tag">${roleLabel(u.rol)}</span>`;
      }
      // Borrar cuenta: SOLO master y no sobre otra cuenta master (el Worker revalida).
      if (ME.rol==='master' && u.rol!=='master'){
        right += `<button class="row-act danger" data-del="${doc.id}">Borrar</button>`;
      }
      row.innerHTML = `
        <div class="ri">${(u.nombre||'?')[0].toUpperCase()}</div>
        <div class="rt"><div class="a">${esc(u.nombre)}</div><div class="b">${esc(u.email||'')} ${u.casa?'· '+esc(u.casa):''}</div></div>
        <div style="display:flex;gap:8px;align-items:center">${right}</div>`;
      list.appendChild(row);
    });
    list.querySelectorAll('[data-susp]').forEach(b=> b.onclick=()=> toggleSuspender(b.dataset.susp, true, b));
    list.querySelectorAll('[data-react]').forEach(b=> b.onclick=()=> toggleSuspender(b.dataset.react, false, b));
    list.querySelectorAll('[data-del]').forEach(b=> b.onclick=()=> abrirUsuarioDelSheet(b.dataset.del, usuariosById[b.dataset.del]));
  } catch(e){ $('#usersList').innerHTML = '<div class="empty">Error cargando usuarios</div>'; }
}

async function toggleSuspender(uid, suspender, btn){
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/usuarios/suspender', { uid, suspendido: suspender });
    toast(suspender ? 'Residente suspendido · no podrá abrir puertas' : 'Residente reactivado', suspender?'bad':'ok');
    loadUsers();
  } catch(e){
    toast(e.message || 'No se pudo actualizar', 'bad');
    btn.disabled = false; btn.textContent = suspender ? 'Suspender' : 'Reactivar';
  }
}

/* Borrado de cuenta (solo master) — confirmación por MODAL, no confirm nativo. El Worker
   borra Auth + doc /usuarios, respalda, y limpia el uid del vecino (reinvitable). */
let usuarioDelId = null;
function abrirUsuarioDelSheet(uid, info){
  usuarioDelId = uid;
  const i = info || {};
  $('#usuarioDelInfo').innerHTML = `<b>${esc(i.nombre||'—')}</b> · ${esc(i.email||'')}${i.casa?' · '+esc(i.casa):''}`;
  $('#usuarioDelErr').textContent = '';
  openSheet('#usuarioDelOverlay');
}
$('#usuarioDelCancel')?.addEventListener('click', () => closeSheet('#usuarioDelOverlay'));
$('#usuarioDelOverlay')?.addEventListener('click', e => { if(e.target.id==='usuarioDelOverlay') closeSheet('#usuarioDelOverlay'); });
$('#usuarioDelConfirm')?.addEventListener('click', async () => {
  if (!usuarioDelId || ME.rol !== 'master') return;
  const btn = $('#usuarioDelConfirm'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/usuarios/borrar', { uid: usuarioDelId });
    toast('Cuenta borrada', 'bad');
    closeSheet('#usuarioDelOverlay');
    loadUsers();
    refrescarVecinos();   // el uid del vecino volvió a null → domicilio reinvitable
  } catch(e){
    $('#usuarioDelErr').textContent = e.message || 'No se pudo borrar';
  } finally { btn.disabled = false; btn.textContent = 'Sí, borrar cuenta'; }
});

/* ====================== VECINOS (padrón · FASE 5) ======================
   Padrón independiente de las cuentas de login. El domicilio es la fuente de verdad
   de las casas en Finanzas. Se lee/escribe SOLO vía Worker (staff). Campos uid/miembros
   quedan reservados para FASE 6; aquí no se usan. */
const normDom = s => String(s||'').trim().replace(/\s+/g,' ').toUpperCase();
function vecinosActivos(){ return vecinosCache.filter(v => v.estado === 'activo'); }

async function cargarVecinos(){
  try {
    const r = await authedFetch('/vecinos/listar', {});
    vecinosCache = Array.isArray(r.vecinos) ? r.vecinos : [];
    // El denominador del termómetro sale del Worker (no se cuenta en el frontend).
    vecinosActivosCount = Number.isInteger(r.activos) ? r.activos : vecinosCache.filter(v=>v.estado==='activo').length;
  } catch(e){ console.error('cargarVecinos', e); vecinosCache = []; vecinosActivosCount = 0; }
}
/* recarga el padrón y refresca TODO lo que depende de él: la lista y, si Finanzas ya se
   pintó, termómetro + morosos (que dependen de los vecinos activos). */
async function refrescarVecinos(){
  await cargarVecinos();
  renderVecinos();
  if (finMonths.length){
    renderTermometro(pagaronDelMes(), vecinosActivosCount);
    renderMorosos();
  }
}
async function loadVecinos(){ await refrescarVecinos(); }

function renderVecinos(){
  const list = $('#vecinosList');
  const raw = $('#vecinoSearch').value.trim();
  const q = normDom(raw);
  let arr = vecinosCache.slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  if (q) arr = arr.filter(v =>
    normDom(v.nombre).includes(q) || (v.domicilioNorm||'').includes(q) || (v.telefono||'').includes(raw));
  if (!arr.length){ list.innerHTML = '<div class="empty">Sin vecinos</div>'; return; }
  list.innerHTML = '';
  arr.forEach(v => {
    const susp = v.estado === 'suspendido';
    const row = document.createElement('div'); row.className = 'row';
    row.innerHTML = `
      <div class="ri">${(v.nombre||'?')[0].toUpperCase()}</div>
      <div class="rt"><div class="a">${esc(v.domicilio)}</div><div class="b">${esc(v.nombre)}${v.telefono?' · '+esc(v.telefono):''}</div></div>
      <div style="display:flex;gap:8px;align-items:center">${susp?'<span class="tag susp">Suspendido</span>':'<span class="tag">Activo</span>'}</div>`;
    const edit = document.createElement('button');
    edit.className = 'row-act'; edit.textContent = 'Editar';
    edit.addEventListener('click', () => abrirVecinoSheet(v));
    row.appendChild(edit);
    // Invitar (FASE 6): solo si el vecino está ACTIVO y aún no tiene cuenta vinculada.
    if (v.estado === 'activo' && !v.uid){
      const inv = document.createElement('button');
      inv.className = 'row-act'; inv.textContent = '📲 Invitar';
      inv.addEventListener('click', () => invitarVecino(v, inv));
      row.appendChild(inv);
    }
    list.appendChild(row);
  });
}
$('#vecinoSearch')?.addEventListener('input', renderVecinos);

let vecinoEditId = null;   // null = alta; id = edición
function abrirVecinoSheet(v){
  vecinoEditId = v ? v.id : null;
  $('#vecinoTitle').textContent = v ? 'Editar vecino' : 'Alta de vecino';
  $('#veName').value   = v?.nombre   || '';
  $('#veCorreo').value = v?.correo   || '';
  $('#veTel').value    = v?.telefono || '';
  $('#veDom').value    = v?.domicilio|| '';
  $('#veEstado').value = v?.estado   || 'activo';
  $('#veEstadoField').classList.toggle('hidden', !v);   // estado solo en edición
  // Borrar: SOLO master y solo en edición (el Worker revalida master + reglas de borrado).
  $('#delVecinoBtn').classList.toggle('hidden', !(v && ME.rol === 'master'));
  $('#veErr').textContent = '';
  $('#saveVecinoBtn').textContent = v ? 'Guardar cambios' : 'Guardar vecino';
  openSheet('#vecinoOverlay');
}
$('#newVecinoBtn')?.addEventListener('click', () => abrirVecinoSheet(null));
$('#vecinoOverlay')?.addEventListener('click', e => { if(e.target.id==='vecinoOverlay') closeSheet('#vecinoOverlay'); });
$('#saveVecinoBtn')?.addEventListener('click', guardarVecino);

async function guardarVecino(){
  const nombre    = $('#veName').value.trim();
  const correo    = $('#veCorreo').value.trim();
  const telefono  = $('#veTel').value.trim();
  const domicilio = $('#veDom').value.trim();
  const estado    = $('#veEstado').value;
  $('#veErr').textContent = '';
  if (!nombre){ $('#veErr').textContent = 'Falta el nombre'; return; }
  if (!telefono){ $('#veErr').textContent = 'El teléfono es obligatorio'; return; }
  if (!domicilio){ $('#veErr').textContent = 'Falta el domicilio'; return; }
  const btn = $('#saveVecinoBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El Worker valida rol staff y el anti-duplicados de domicilio server-side.
    if (vecinoEditId){
      await authedFetch('/vecinos/actualizar', { id: vecinoEditId, nombre, correo, telefono, domicilio, estado });
      toast('Vecino actualizado', 'ok');
    } else {
      await authedFetch('/vecinos/crear', { nombre, correo, telefono, domicilio });
      toast('Vecino dado de alta', 'ok');
    }
    closeSheet('#vecinoOverlay');
    await refrescarVecinos();
  } catch(e){
    $('#veErr').textContent = e.message || 'No se pudo guardar';
  } finally {
    btn.disabled = false; btn.textContent = vecinoEditId ? 'Guardar cambios' : 'Guardar vecino';
  }
}

/* Borrado de vecino (solo master) — confirmación por MODAL, no confirm nativo.
   El Worker revalida master, bloquea si hay pagos y respalda a vecinos_borrados. */
$('#delVecinoBtn')?.addEventListener('click', () => {
  if (!vecinoEditId || ME.rol !== 'master') return;
  const v = vecinosCache.find(x => x.id === vecinoEditId);
  $('#vecinoDelInfo').innerHTML = `<b>${esc(v?.domicilio || '')}</b> · ${esc(v?.nombre || '')}`;
  $('#vecinoDelErr').textContent = '';
  openSheet('#vecinoDelOverlay');
});
$('#vecinoDelCancel')?.addEventListener('click', () => closeSheet('#vecinoDelOverlay'));
$('#vecinoDelOverlay')?.addEventListener('click', e => { if(e.target.id==='vecinoDelOverlay') closeSheet('#vecinoDelOverlay'); });
$('#vecinoDelConfirm')?.addEventListener('click', async () => {
  if (!vecinoEditId || ME.rol !== 'master') return;
  const btn = $('#vecinoDelConfirm'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/vecinos/borrar', { id: vecinoEditId });
    toast('Vecino borrado', 'bad');
    closeSheet('#vecinoDelOverlay');
    closeSheet('#vecinoOverlay');
    await refrescarVecinos();
  } catch(e){
    $('#vecinoDelErr').textContent = e.message || 'No se pudo borrar';
  } finally {
    btn.disabled = false; btn.textContent = 'Sí, borrar';
  }
});

/* Invitación por WhatsApp (FASE 6). El token lo genera el Worker; el link se arma desde
   location.origin (sirve en local y prod). SIEMPRE Web Share; jamás wa.me ni pestañas
   nuevas. Plan B: modal con "Copiar link" si navigator.share no existe. */
async function invitarVecino(v, btn){
  const orig = btn.textContent; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await authedFetch('/invitaciones/crear', { vecinoId: v.id });
    const url = new URL('registro.html', location.href).href + '#' + r.token;
    const texto = `Hola, te invito a registrarte en la app de Cerrada Mixcoac para el domicilio ${v.domicilio}. Abre este enlace (vence en 72 h):`;
    if (navigator.share){
      try { await navigator.share({ title:'Cerrada Mixcoac', text: texto, url }); }
      catch(e){ if (!(e && e.name === 'AbortError')) throw e; }   // AbortError = el usuario canceló
    } else {
      abrirInviteFallback(v, url);   // Plan B
    }
  } catch(e){
    toast(e.message || 'No se pudo generar la invitación', 'bad');
  } finally { btn.disabled = false; btn.textContent = orig; }
}

let inviteFallbackUrl = null;
function abrirInviteFallback(v, url){
  inviteFallbackUrl = url;
  $('#inviteFallbackInfo').innerHTML = `<b>${esc(v.domicilio)}</b> · ${esc(v.nombre)}`;
  $('#inviteFallbackLink').value = url;
  openSheet('#inviteFallbackOverlay');
}
$('#inviteFallbackClose')?.addEventListener('click', () => closeSheet('#inviteFallbackOverlay'));
$('#inviteFallbackOverlay')?.addEventListener('click', e => { if(e.target.id==='inviteFallbackOverlay') closeSheet('#inviteFallbackOverlay'); });
$('#inviteCopyBtn')?.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(inviteFallbackUrl);
    toast('Link copiado', 'ok');
  } catch(e){
    $('#inviteFallbackLink').select(); document.execCommand('copy');
    toast('Link copiado', 'ok');
  }
});

/* ====================== FINANZAS ====================== */
let movType = 'ingreso';
let finCache = [];      // movimientos de los últimos 6 meses (solo lectura)
let finMonths = [];     // [{key,start,end,label}] los últimos 6 meses, más viejo primero
let finCharts = { barras:null, pastel:null, linea:null };
// Paleta compartida: colores de las categorías en la dona del PDF y su leyenda nativa (mismo orden,
// gama sobria para papel: dorado, ocre, terracota, verde seco + tonos tierra de respaldo).
const DOUGHNUT_PALETTE = ['#d4a017', '#d97706', '#b7472a', '#6b8e63', '#8a6d3b', '#94a3b8'];
function hexToRgb(hex){
  const n = parseInt(hex.replace('#',''), 16);
  return [(n>>16)&255, (n>>8)&255, n&255];
}
// Identidad visual del PDF "despacho contable" (FASE 0 del plan maestro).
const PDF = {
  text: [17,24,39],        // #111827 — nunca negro puro
  secondary: [100,116,139],// #64748b
  notes: [156,163,175],    // #9ca3af
  gold: [212,160,23],      // #d4a017 — solo filetes/acentos
  green: [15,118,110],     // #0f766e — ingresos
  red: [153,27,27],        // #991b1b — gastos
  navy: [30,58,138],       // #1e3a8a — saldo
  grid: [226,232,240],     // #e2e8f0
  zebra: [248,250,252],    // #f8fafc
  badgeGreenBg: [204,251,241], badgeGreenFg: [15,118,110],
  badgeRedBg: [254,226,226], badgeRedFg: [153,27,27],
  MARGIN: 25 * 72 / 25.4,  // 25mm en pt
};
/* folio determinista FIN-YYYYMM-### — no hay contador persistente en Firestore (fuera de alcance
   escribir uno sin autorización), así que se deriva de mes+totales: estable mientras no cambien
   los movimientos del mes, único por combinación mes/monto. */
function folioDelMes(curKey, cobrado, gastos){
  const seed = curKey.replace('-','') + '|' + Math.round(cobrado) + '|' + Math.round(gastos);
  let hash = 0;
  for (let i=0;i<seed.length;i++) hash = (hash*31 + seed.charCodeAt(i)) >>> 0;
  const num = (hash % 900) + 100;
  return `FIN-${curKey.replace('-','')}-${num}`;
}

function monthRange(){
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 1);
  const end = new Date(now.getFullYear(), now.getMonth()+1, 1);
  return { start, end, label: now.toLocaleDateString('es-MX',{month:'long',year:'numeric'}) };
}
function last6Months(){
  const now = new Date();
  const arr = [];
  for (let i=5; i>=0; i--){
    const d = new Date(now.getFullYear(), now.getMonth()-i, 1);
    arr.push({
      key: d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'),
      start: new Date(d.getFullYear(), d.getMonth(), 1),
      end: new Date(d.getFullYear(), d.getMonth()+1, 1),
      label: d.toLocaleDateString('es-MX',{month:'short',year:'2-digit'}),
    });
  }
  return arr;
}
const money = n => '$'+(n||0).toLocaleString('es-MX',{minimumFractionDigits:0,maximumFractionDigits:2});
const monthKey = ts => { const d = ts.toDate ? ts.toDate() : new Date(ts); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'); };

function watchFinanzas(){
  if (unsubFin) unsubFin();
  const isStaff = (ME.rol==='master' || ME.rol==='admin');

  // Detalle de movimientos, gráficas y morosos: solo staff. Residentes/esclavos ya no
  // leen "finanzas" directo (bloqueado por Firestore rules) — reciben solo el agregado
  // del Worker, nunca el detalle por casa.
  $('#newMovBtn').style.display = isStaff ? 'block' : 'none';
  $('#finCharts').classList.toggle('hidden', !isStaff);
  $('#finActionsMain').classList.toggle('hidden', !isStaff);
  $('#finActionsShare').classList.toggle('hidden', !isStaff);
  $('#morososSection').classList.toggle('hidden', !isStaff);
  $('#finDetalle').classList.toggle('hidden', !isStaff);

  finMonths = last6Months();
  const { label } = monthRange();
  $('#finMonth').textContent = 'Finanzas · ' + label;

  if (isStaff){
    // FASE 5: el padrón alimenta termómetro/morosos/dropdown; se recarga al entrar
    // (y tras cada alta/edición vía refrescarVecinos). No hay lectura directa de vecinos.
    cargarVecinos().then(() => {
      renderTermometro(pagaronDelMes(), vecinosActivosCount);
      renderMorosos();
    });
    unsubFin = db.collection('finanzas')
      .where('ts','>=',finMonths[0].start)
      .orderBy('ts','desc').limit(1200)
      .onSnapshot(snap => {
        finCache = [];
        snap.forEach(doc => finCache.push({ id: doc.id, ...doc.data() }));
        renderFinanzas();
      }, err => { console.error(err); $('#movList').innerHTML='<div class="empty">Sin acceso a finanzas</div>'; });
  } else {
    loadResumenResidente();
  }
}

/* -------- resumen agregado para residentes/esclavos (vía Worker) -------- */
async function loadResumenResidente(){
  try {
    const r = await authedFetch('/finanzas/resumen', {});
    $('#finCobrado').textContent = money(r.ingreso);
    $('#finGastos').textContent = money(r.egreso);
    $('#finCaja').textContent = money(r.balance);
    renderTermometro(r.pagaron, r.totalCasas);
  } catch(e){
    console.error(e);
    $('#thermText').textContent = 'No se pudo cargar la información financiera.';
  }
}

/* -------- termómetro "X de Y casas pagaron" (compartido staff/residente) -------- */
function renderTermometro(pagaron, totalCasas){
  const fill = $('#thermFill');
  if (!totalCasas){
    fill.style.width = '0%';
    fill.className = 'therm-fill';
    const isStaff = (ME.rol==='master' || ME.rol==='admin');
    $('#thermText').textContent = isStaff
      ? 'Da de alta vecinos en Gestión para activar el termómetro.'
      : 'El termómetro aún no está disponible.';
    return;
  }
  const pct = Math.round((pagaron / totalCasas) * 100);
  const color = pct >= 80 ? 'ok' : pct >= 50 ? 'warn' : 'bad';
  fill.style.width = Math.min(pct, 100) + '%';
  fill.className = 'therm-fill therm-' + color;
  $('#thermText').textContent = `${pagaron} de ${totalCasas} casas pagaron (${pct}%)`;
}

/* -------- fuente ÚNICA: Map(domicilioNorm → pago) de casas que pagaron Cuota este mes.
   Compartida por termómetro, morosos y "consultar casa" — no vuelven a divergir. El
   domicilio guardado en finanzas ya es el canónico del padrón; se normaliza igual que en
   el Worker (MAYÚSCULAS) para casar con vecinosCache. -------- */
function pagosPorCasaDelMes(){
  const curKey = monthKey(new Date());
  const map = new Map();
  finCache.forEach(m => {
    if (m.tipo==='ingreso' && (m.categoria||'')==='Cuota' && monthKey(m.ts)===curKey && m.casa) {
      const k = normDom(m.casa);
      if (!map.has(k)) map.set(k, m);   // finCache viene desc por ts → conserva el más reciente
    }
  });
  return map;
}
function pagaronDelMes(){ return pagosPorCasaDelMes().size; }

/* -------- lista de morosos del mes (solo staff) — colapsable, cerrada por default.
   Universo = vecinos ACTIVOS del padrón (suspendidos no se cobran ni son morosos). -------- */
let morososExpandido = false;
function renderMorosos(){
  const list = $('#morososList');
  const countEl = $('#morososCount');
  const toggle = $('#morososToggle');

  poblarConsultaCasa();

  const activos = vecinosActivos();
  if (!activos.length){
    countEl.textContent = 'Sin vecinos activos';
    list.innerHTML = '<div class="empty">Da de alta vecinos en Gestión para ver morosos</div>';
    list.classList.toggle('hidden', !morososExpandido);
    toggle.classList.toggle('abierto', morososExpandido);
    return;
  }

  const pagados = pagosPorCasaDelMes();
  const morosos = activos.filter(v => !pagados.has(v.domicilioNorm));
  const activosNorm = new Set(activos.map(v => v.domicilioNorm));
  const noReconocidos = [...pagados.entries()].filter(([k]) => !activosNorm.has(k));

  countEl.textContent = `${morosos.length} casa${morosos.length===1?'':'s'} sin pago`;

  let html = morosos.length
    ? morosos.map(v => `<div class="row"><div class="rt"><div class="a">${esc(v.domicilio)}</div></div><span class="tag out">Sin pago</span></div>`).join('')
    : '<div class="empty">Todas las casas están al corriente</div>';
  if (noReconocidos.length){
    html += `<div class="section-title" style="margin-top:14px;font-size:12px">No reconocidos (fuera del padrón activo)</div>` +
      noReconocidos.map(([,m]) => `<div class="row"><div class="rt"><div class="a">${esc(m.casa)}</div></div><span class="tag">Revisar</span></div>`).join('');
  }
  list.innerHTML = html;
  list.classList.toggle('hidden', !morososExpandido);
  toggle.classList.toggle('abierto', morososExpandido);
}
$('#morososToggle').addEventListener('click', () => {
  morososExpandido = !morososExpandido;
  $('#morososList').classList.toggle('hidden', !morososExpandido);
  $('#morososToggle').classList.toggle('abierto', morososExpandido);
});

/* -------- consultar el estado de un domicilio del padrón (solo staff) -------- */
function poblarConsultaCasa(){
  const sel = $('#consultaCasaSel');
  const activos = vecinosActivos().slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  const prev = sel.value;
  sel.innerHTML = '';
  if (!activos.length){ sel.appendChild(new Option('—','')); renderConsultaCasa(); return; }
  sel.appendChild(new Option('Elige un domicilio…',''));
  activos.forEach(v => sel.appendChild(new Option(v.domicilio, v.domicilio)));   // new Option escapa seguro
  if (prev) sel.value = prev;
  renderConsultaCasa();
}
function renderConsultaCasa(){
  const box = $('#consultaCasaResult');
  const casa = $('#consultaCasaSel').value;
  if (!casa){ box.classList.add('hidden'); box.classList.remove('pagado'); return; }
  const pago = pagosPorCasaDelMes().get(normDom(casa));
  box.classList.remove('hidden');
  if (pago){
    box.classList.add('pagado');
    box.innerHTML = `<div class="a">${esc(casa)} · <b>pagó</b></div>`
      + `<div class="sub">${esc(pago.folioRecibo||'sin folio')} · ${money(pago.monto)} · ${fmtTime(pago.ts)}</div>`;
  } else {
    box.classList.remove('pagado');
    box.innerHTML = `<div class="a">${esc(casa)} · sin pago este mes</div>`
      + `<div class="sub">No hay Cuota registrada para este domicilio en el mes en curso.</div>`;
  }
}
$('#consultaCasaSel').addEventListener('change', renderConsultaCasa);

function groupByMonth(){
  const map = {};
  finMonths.forEach(m => map[m.key] = { ingreso:0, gasto:0 });
  finCache.forEach(m => {
    const k = monthKey(m.ts);
    if (!map[k]) return; // fuera de la ventana de 6 meses visible
    if (m.tipo==='ingreso') map[k].ingreso += m.monto; else map[k].gasto += m.monto;
  });
  return map;
}

function renderCmp(el, cur, prev, higherIsBetter){
  if (!cur && !prev){ el.innerHTML = '<span class="muted">Sin datos mes pasado</span>'; return; }
  if (!prev){ el.innerHTML = '<span class="muted">Sin datos mes pasado</span>'; return; }
  const pct = ((cur - prev) / prev) * 100;
  const up = pct >= 0;
  const good = higherIsBetter ? up : !up;
  el.innerHTML = `<span class="${good?'ok':'bad'}">${up?'▲':'▼'}${Math.abs(pct).toFixed(0)}% vs mes pasado</span>`;
}

function renderFinanzas(){
  const byMonth = groupByMonth();
  const curKey = finMonths[finMonths.length-1].key;
  const prevKey = finMonths[finMonths.length-2].key;
  const cur = byMonth[curKey], prev = byMonth[prevKey];

  const cobrado = cur.ingreso, gastos = cur.gasto, caja = cur.ingreso - cur.gasto;
  const prevCaja = prev.ingreso - prev.gasto;

  $('#finCobrado').textContent = money(cobrado);
  $('#finGastos').textContent = money(gastos);
  $('#finCaja').textContent = money(caja);

  renderCmp($('#cmpCobrado'), cobrado, prev.ingreso, true);
  renderCmp($('#cmpGastos'), gastos, prev.gasto, false);
  renderCmp($('#cmpCaja'), caja, prevCaja, true);

  renderFinCharts(byMonth, curKey);
  populateFiltros();
  filterAndRenderMovs();
  renderTermometro(pagaronDelMes(), vecinosActivosCount);
  renderMorosos();
}

/* -------- gastos por categoría del mes (compartido: dashboard + PDF) -------- */
function categoriasDelMes(curKey){
  const catTotals = {};
  finCache.filter(m => m.tipo==='egreso' && monthKey(m.ts)===curKey).forEach(m => {
    const c = m.categoria || 'Otro';
    catTotals[c] = (catTotals[c]||0) + m.monto;
  });
  const labels = Object.keys(catTotals);
  return {
    labels,
    data: labels.map(c=>catTotals[c]),
    hasData: labels.length > 0,
  };
}

/* meses con al menos un movimiento (para no graficar 5 meses vacíos en el PDF) */
function mesesConMovimientos(byMonth){
  const activos = finMonths.filter(m => byMonth[m.key].ingreso > 0 || byMonth[m.key].gasto > 0);
  const usados = activos.length ? activos : [finMonths[finMonths.length-1]];
  return {
    labels: usados.map(m => m.label),
    ingresos: usados.map(m => byMonth[m.key].ingreso),
    gastos: usados.map(m => byMonth[m.key].gasto),
  };
}

/* -------- gráficas (Chart.js) -------- */
function renderFinCharts(byMonth, curKey){
  if (typeof Chart === 'undefined') return;
  const gold='#d4af37', goldSoft='#e8c468', ok='#34d399', bad='#f87171', muted='#a1a1aa', text='#f5f5f4', line='#2a2a30';

  const labels = finMonths.map(m => m.label);
  const ingresos = finMonths.map(m => byMonth[m.key].ingreso);
  const gastosArr = finMonths.map(m => byMonth[m.key].gasto);
  const saldos = finMonths.map(m => byMonth[m.key].ingreso - byMonth[m.key].gasto);

  if (finCharts.barras) finCharts.barras.destroy();
  finCharts.barras = new Chart($('#chartBarras'), {
    type:'bar',
    data:{ labels, datasets:[
      { label:'Ingresos', data:ingresos, backgroundColor:ok, borderRadius:4, maxBarThickness:26 },
      { label:'Gastos', data:gastosArr, backgroundColor:bad, borderRadius:4, maxBarThickness:26 },
    ]},
    options:{ responsive:true, plugins:{ legend:{ labels:{ color:text } } },
      scales:{ x:{ ticks:{ color:muted }, grid:{ color:line } }, y:{ ticks:{ color:muted }, grid:{ color:line }, beginAtZero:true } } }
  });

  const { labels: catLabels, data: catData, hasData } = categoriasDelMes(curKey);
  const palette = [gold, goldSoft, ok, bad, muted, '#9c7d1e', '#3b82f6'];

  if (finCharts.pastel){ finCharts.pastel.destroy(); finCharts.pastel = null; }
  $('#chartPastel').classList.toggle('hidden', !hasData);
  $('#chartPastelEmpty').classList.toggle('hidden', hasData);
  if (hasData){
    finCharts.pastel = new Chart($('#chartPastel'), {
      type:'doughnut',
      data:{
        labels: catLabels,
        datasets:[{
          data: catData,
          backgroundColor: catLabels.map((_,i)=>palette[i%palette.length]),
        }],
      },
      options:{ responsive:true, cutout:'55%', plugins:{ legend:{ position:'bottom', labels:{ color:text, boxWidth:12 } } } }
    });
  }

  if (finCharts.linea) finCharts.linea.destroy();
  finCharts.linea = new Chart($('#chartLinea'), {
    type:'line',
    data:{ labels, datasets:[{
      label:'Saldo en caja', data:saldos, borderColor:gold, backgroundColor:'rgba(212,175,55,.15)',
      fill:true, tension:.35, pointBackgroundColor:gold,
    }]},
    options:{ responsive:true, plugins:{ legend:{ display:false } },
      scales:{ x:{ ticks:{ color:muted }, grid:{ color:line } }, y:{ ticks:{ color:muted }, grid:{ color:line } } } }
  });
}
function resizeFinCharts(){
  requestAnimationFrame(()=> Object.values(finCharts).forEach(c => c && c.resize()));
}

/* -------- barras (Ingresos vs Gastos) en alta resolución, solo para el PDF --------
   Colores de la identidad "despacho contable" (verde/rojo oscuros, legibles en papel blanco).
   Sin leyenda horneada — esa va como texto nativo (ver dibujarLeyendaSeries). Valores encima
   de cada barra vía plugin propio (afterDatasetsDraw), grid casi invisible. */
async function renderBarrasHiRes(labels, ingresos, gastos){
  const off = document.createElement('canvas');
  off.width = 1400; off.height = 700;

  const valueLabelsPlugin = {
    id: 'valueLabels',
    afterDatasetsDraw(chart){
      const { ctx } = chart;
      chart.data.datasets.forEach((dataset, di) => {
        const meta = chart.getDatasetMeta(di);
        meta.data.forEach((bar, i) => {
          const value = dataset.data[i];
          if (!value) return;
          ctx.save();
          ctx.fillStyle = '#111827';
          ctx.font = 'bold 20px Helvetica, Arial, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(money(value), bar.x, bar.y - 12);
          ctx.restore();
        });
      });
    },
  };

  const chart = new Chart(off, {
    type:'bar',
    data:{ labels, datasets:[
      { label:'Ingresos', data:ingresos, backgroundColor:'#0f766e', borderRadius:6, maxBarThickness:46 },
      { label:'Gastos', data:gastos, backgroundColor:'#991b1b', borderRadius:6, maxBarThickness:46 },
    ]},
    options:{
      responsive:false, animation:false,
      layout:{ padding:{ top:36 } },
      plugins:{ legend:{ display:false }, tooltip:{ enabled:false } },
      scales:{
        x:{ ticks:{ color:'#64748b', font:{ size:22 } }, grid:{ display:false } },
        y:{ ticks:{ color:'#64748b', font:{ size:20 } }, grid:{ color:'#e2e8f0' }, beginAtZero:true },
      },
    },
    plugins: [valueLabelsPlugin],
  });
  await new Promise(r => setTimeout(r, 0));
  const dataUrl = off.toDataURL('image/png');
  chart.destroy();
  return dataUrl;
}
/* leyenda nativa simple (swatch + texto) para series de una gráfica, ej. Ingresos/Gastos */
function dibujarLeyendaSeries(doc, W, gy, items){
  const itemW = 110;
  let x = (W - items.length*itemW) / 2;
  items.forEach(({label, color}) => {
    doc.setFillColor(...hexToRgb(color));
    doc.roundedRect(x, gy, 12, 12, 3, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(10); doc.setTextColor(...PDF.text);
    doc.text(label, x + 18, gy + 10);
    x += itemW;
  });
  return gy + 12 + 14;
}

/* -------- doughnut de gastos en alta resolución, solo para el PDF --------
   Solo el círculo (+ total al centro): sin leyenda ni etiquetas de categoría horneadas en la
   imagen — esas van como texto nativo del PDF (ver dibujarLeyendaCategorias), para que queden
   nítidas a cualquier zoom en vez de pixeleadas dentro de un PNG. */
async function renderPastelDoughnutHiRes(catLabels, catData, hasData, totalTexto){
  // sin gastos: anillo gris de relleno solo dentro de esta imagen (el dato falso no sale de aquí)
  if (!hasData){ catLabels = ['Sin gastos']; catData = [1]; }
  const SIZE = 900; // px reales del canvas (cuadrado, > 800 mínimo pedido)
  const off = document.createElement('canvas');
  off.width = SIZE; off.height = SIZE;

  const shadowPlugin = {
    id: 'donutShadow',
    beforeDatasetDraw(chart){
      const ctx = chart.ctx;
      ctx.save();
      ctx.shadowColor = 'rgba(0,0,0,.30)';
      ctx.shadowBlur = 22;
      ctx.shadowOffsetX = 0;
      ctx.shadowOffsetY = 8;
    },
    afterDatasetDraw(chart){ chart.ctx.restore(); },
  };
  const centerTextPlugin = {
    id: 'centerText',
    afterDraw(chart){
      const { ctx, chartArea } = chart;
      if (!chartArea) return;
      const cx = (chartArea.left + chartArea.right) / 2;
      const cy = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillStyle = '#111827';
      ctx.font = 'bold 46px Helvetica, Arial, sans-serif';
      ctx.fillText(totalTexto, cx, cy - 16);
      ctx.fillStyle = '#64748b';
      ctx.font = '24px Helvetica, Arial, sans-serif';
      ctx.fillText('Total gastos', cx, cy + 28);
      ctx.restore();
    },
  };

  const chart = new Chart(off, {
    type:'doughnut',
    data:{
      labels: catLabels,
      datasets:[{
        data: catData,
        backgroundColor: hasData ? catLabels.map((_,i)=>DOUGHNUT_PALETTE[i%DOUGHNUT_PALETTE.length]) : ['#d8d8d8'],
        borderColor:'#ffffff',
        borderWidth:4,
      }],
    },
    options:{
      responsive:false,
      animation:false,
      devicePixelRatio:1,
      cutout:'55%',
      layout:{ padding:24 },
      plugins:{ legend:{ display:false }, tooltip:{ enabled:false } },
    },
    plugins: [shadowPlugin, centerTextPlugin],
  });

  // Con animation:false, Chart.js ya pintó de forma síncrona. Se usa setTimeout (no rAF)
  // porque rAF nunca se dispara si la pestaña está en segundo plano al generar el PDF.
  await new Promise(r => setTimeout(r, 0));
  const dataUrl = off.toDataURL('image/png');
  chart.destroy();
  return dataUrl;
}

/* leyenda nativa del PDF: cuadrito de color + nombre + porcentaje + monto, texto real (no imagen).
   `x0` permite dibujarla a la derecha de la dona en vez de a todo el ancho. */
function dibujarLeyendaCategorias(doc, W, gy, catLabels, catData, hasData, x0, x1){
  x0 = x0 ?? 40; x1 = x1 ?? (W - 40);
  if (!hasData){
    doc.setFont('helvetica','normal'); doc.setFontSize(10); doc.setTextColor(...PDF.notes);
    doc.text('Sin gastos registrados este mes.', x0, gy + 14);
    return gy + 26;
  }
  const total = catData.reduce((a,b)=>a+b, 0) || 1;
  const rowH = 24;
  catLabels.forEach((catLabel, i) => {
    const y = gy + i*rowH;
    doc.setFillColor(...hexToRgb(DOUGHNUT_PALETTE[i % DOUGHNUT_PALETTE.length]));
    doc.roundedRect(x0, y, 12, 12, 3, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(10.5); doc.setTextColor(...PDF.text);
    doc.text(catLabel, x0 + 18, y + 10);
    const pct = Math.round(catData[i] / total * 100);
    doc.setFont('courier','bold'); doc.setFontSize(9.5); doc.setTextColor(...PDF.secondary);
    doc.text(`${pct}% · ${money(catData[i])}`, x1, y + 10, { align:'right' });
  });
  return gy + catLabels.length*rowH + 12;
}

/* indicador de salud financiera: barra proporción gastos/ingresos + línea de lectura */
function dibujarSaludFinanciera(doc, W, gy, cobrado, gastos){
  const x0 = PDF.MARGIN, x1 = W - PDF.MARGIN, barW = x1 - x0, barH = 8;
  if (!(cobrado > 0)){
    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.notes);
    doc.text('Sin datos suficientes para el indicador de salud financiera este mes.', x0, gy + 10);
    return gy + 24;
  }
  const pct = Math.min(gastos / cobrado, 1);
  const color = pct < 0.5 ? PDF.green : pct < 0.8 ? PDF.gold : PDF.red;
  doc.setFillColor(...PDF.grid);
  doc.roundedRect(x0, gy, barW, barH, 4, 4, 'F');
  doc.setFillColor(...color);
  doc.roundedRect(x0, gy, Math.max(barW*pct, barH), barH, 4, 4, 'F');
  doc.setFont('helvetica','normal'); doc.setFontSize(9.5); doc.setTextColor(...PDF.secondary);
  const pctTxt = Math.round(pct*100);
  doc.text(`Los gastos representan el ${pctTxt}% de lo recaudado este mes.`, x0, gy + barH + 14);
  return gy + barH + 28;
}

/* -------- filtros (100% client-side sobre finCache) -------- */
// Las 8 categorías fijas siempre visibles en el filtro (mismo orden que el <select> de registro).
const CATEGORIAS_FIJAS = ['Cuota','Multa','Mantenimiento','Seguridad','Limpieza','Mejoras','Servicios','Otro'];
function populateFiltros(){
  const selCat = $('#filtroCategoria');
  const curCat = selCat.value;
  // Fijas primero; si algún movimiento viejo trae una categoría fuera de la lista, se agrega al final.
  const extras = [...new Set(finCache.map(m=>m.categoria||'Otro'))].filter(c=>!CATEGORIAS_FIJAS.includes(c)).sort();
  const cats = [...CATEGORIAS_FIJAS, ...extras];
  selCat.innerHTML = '<option value="">Todas las categorías</option>' + cats.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('');
  selCat.value = cats.includes(curCat) ? curCat : '';

  const selMes = $('#filtroMes');
  const curMes = selMes.value;
  selMes.innerHTML = '<option value="">Todos los meses</option>' + finMonths.slice().reverse().map(m=>`<option value="${m.key}">${esc(m.label)}</option>`).join('');
  selMes.value = finMonths.some(m=>m.key===curMes) ? curMes : '';
}
function filterAndRenderMovs(){
  const cat = $('#filtroCategoria').value;
  const mes = $('#filtroMes').value;
  let list = finCache;
  if (cat) list = list.filter(m => (m.categoria||'Otro') === cat);
  if (mes) list = list.filter(m => monthKey(m.ts) === mes);
  renderMovs(list);
}
$('#filtroCategoria').addEventListener('change', filterAndRenderMovs);
$('#filtroMes').addEventListener('change', filterAndRenderMovs);

function renderMovs(movs){
  const list = $('#movList');
  if (!movs.length){ list.innerHTML = '<div class="empty">Sin movimientos</div>'; return; }
  list.innerHTML = '';
  movs.forEach(m => {
    const ing = m.tipo==='ingreso';
    const row = document.createElement('div'); row.className = 'row';
    const folioLinea = (ing && m.folioRecibo) ? `<div class="mov-folio">${esc(m.folioRecibo)}${m.casa ? ' · '+esc(m.casa) : ''}</div>` : '';
    row.innerHTML = `
      <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ing?'<path d="M12 19V5 M5 12l7-7 7 7"/>':'<path d="M12 5v14 M19 12l-7 7-7-7"/>'}</svg></div>
      <div class="rt"><div class="a">${esc(m.concepto||m.categoria)}</div><div class="b">${esc(m.categoria)} · ${fmtTime(m.ts)}</div>${folioLinea}</div>
      <span class="mov-amt ${ing?'ok':'bad'}">${ing?'+':'−'}${money(m.monto)}</span>`;
    if (ing && m.folioRecibo){
      const act = document.createElement('button');
      act.className = 'row-act recibo'; act.textContent = 'Recibo';
      act.addEventListener('click', () => abrirReciboSheet(m));
      row.appendChild(act);
    }
    // Borrar: SOLO master. El Worker respalda el doc en finanzas_borrados antes de eliminar.
    if (ME.rol === 'master'){
      const del = document.createElement('button');
      del.className = 'row-act danger'; del.textContent = 'Borrar';
      del.addEventListener('click', () => borrarMovimiento(m, del));
      row.appendChild(del);
    }
    list.appendChild(row);
  });
}

/* Borrado de un movimiento (solo master). Confirmación explícita porque es
   destructivo; el snapshot de watchFinanzas redibuja la lista al eliminarse. */
async function borrarMovimiento(m, btn){
  const detalle = `${m.tipo==='ingreso'?'+':'−'}${money(m.monto)} · ${m.concepto||m.categoria}` +
    (m.folioRecibo ? ` · ${m.folioRecibo}` : '');
  if (!confirm(`¿Borrar este movimiento?\n\n${detalle}\n\nSe conserva un respaldo, pero desaparece del reporte.`)) return;
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await authedFetch('/finanzas/borrar', { id: m.id });
    toast('Movimiento borrado', 'bad');
    // La lista se actualiza sola por el onSnapshot de finanzas.
  } catch(e){
    toast(e.message || 'No se pudo borrar', 'bad');
    btn.disabled = false; btn.textContent = 'Borrar';
  }
}

/* registrar movimiento (solo staff) */
/* FASE 4.5: casa obligatoria en TODO ingreso — cada recibo queda amarrado a una casa. */
function casaRequerida(){ return movType==='ingreso'; }
/* FASE 5: el campo Domicilio es un dropdown con los domicilios de vecinos ACTIVOS del
   padrón (ya no números 1..N ni texto libre) — el Worker revalida contra el padrón. */
function poblarCasaSelect(){
  const sel = $('#movCasa');
  const activos = vecinosActivos().slice().sort((a,b)=>a.domicilio.localeCompare(b.domicilio,'es',{numeric:true}));
  const prev = sel.value;
  sel.innerHTML = '';
  if (!activos.length){
    sel.appendChild(new Option('Da de alta vecinos primero',''));
    sel.disabled = true; return;
  }
  sel.disabled = false;
  sel.appendChild(new Option('Selecciona el domicilio…',''));
  activos.forEach(v => sel.appendChild(new Option(v.domicilio, v.domicilio)));
  if (prev) sel.value = prev;   // conserva selección si sigue en el padrón
}
function updateCasaField(){
  const req = casaRequerida();
  $('#movCasaField').classList.toggle('hidden', !req);
  if (req) poblarCasaSelect();
}
$('#newMovBtn').addEventListener('click', ()=>{ $('#movErr').textContent=''; updateCasaField(); openSheet('#movOverlay'); });
$('#movOverlay').addEventListener('click', e => { if(e.target.id==='movOverlay') closeSheet('#movOverlay'); });
$('#movTypeSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if(!b) return;
  $$('#movTypeSeg button').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); movType = b.dataset.t;
  updateCasaField();
});
$('#movCat').addEventListener('change', updateCasaField);
$('#saveMovBtn').addEventListener('click', saveMov);

async function saveMov(){
  const concepto = $('#movConcept').value.trim();
  const categoria = $('#movCat').value.trim() || 'Otro';
  const monto = parseFloat($('#movAmount').value);
  const casa = $('#movCasa').value;  // FASE 4.6: dropdown numérico → "1".."totalCasas" o ""
  $('#movErr').textContent = '';
  if (!concepto || !(monto > 0)){ $('#movErr').textContent = 'Falta concepto o monto válido'; return; }
  if (casaRequerida() && !casa){ $('#movErr').textContent = 'Selecciona la casa (obligatorio en ingresos)'; return; }
  const btn = $('#saveMovBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El movimiento lo escribe el Worker tras verificar rol master/admin.
    // En ingresos el Worker además asigna el folio consecutivo del recibo.
    const r = await authedFetch('/finanzas/registrar', { tipo: movType, concepto, categoria, monto, casa });
    toast('Movimiento registrado', 'ok');
    closeSheet('#movOverlay');
    $('#movConcept').value = $('#movCat').value = $('#movAmount').value = $('#movCasa').value = '';
    if (r && r.folioRecibo){
      abrirReciboSheet({
        id: r.id, folioRecibo: r.folioRecibo,
        tipo: movType, concepto, categoria, monto, casa,
        creadoNombre: ME.nombre || '', ts: new Date(),
      });
    }
  } catch(e){ $('#movErr').textContent = e.message || 'No se pudo guardar'; }
  finally { btn.disabled = false; btn.textContent = 'Guardar movimiento'; }
}

/* reporte PDF para el grupo de residentes */
$('#pdfBtn').addEventListener('click', generarPDF);

/* construye el PDF premium (FASE 0) y devuelve {doc, filename} sin descargar ni compartir —
   generarPDF() y compartirReportePDF() comparten esta misma construcción. */
async function construirReportePDF(){
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit:'pt', format:'letter' });
    const W = doc.internal.pageSize.getWidth();
    const H = doc.internal.pageSize.getHeight();
    const M = PDF.MARGIN;
    const { label } = monthRange();

    // finCache trae 6 meses; el reporte PDF es mensual, así que se filtra al mes en curso.
    const curKey = finMonths.length ? finMonths[finMonths.length-1].key : monthKey(new Date());
    const prevKey = finMonths.length > 1 ? finMonths[finMonths.length-2].key : null;
    const monthMovs = finCache.filter(m => monthKey(m.ts) === curKey);

    let cobrado = 0, gastos = 0;
    monthMovs.forEach(m => m.tipo==='ingreso' ? cobrado += m.monto : gastos += m.monto);
    const saldo = cobrado - gastos;

    const byMonth = groupByMonth();
    const prevMonth = prevKey ? byMonth[prevKey] : null;
    const cmpPct = (cur, prevVal) => (prevVal > 0) ? Math.round(((cur - prevVal) / prevVal) * 100) : null;
    const cmpCobrado = prevMonth ? cmpPct(cobrado, prevMonth.ingreso) : null;
    const cmpGastos = prevMonth ? cmpPct(gastos, prevMonth.gasto) : null;
    const prevSaldo = prevMonth ? (prevMonth.ingreso - prevMonth.gasto) : null;
    const cmpSaldo = (prevMonth && prevSaldo !== 0) ? Math.round(((saldo - prevSaldo) / Math.abs(prevSaldo)) * 100) : null;

    const folio = folioDelMes(curKey, cobrado, gastos);
    const generadoEl = new Date().toLocaleString('es-MX', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });

    /* ===== 1. Filete dorado + encabezado ===== */
    doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');

    let y = M - 10;
    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text('E S T A D O   D E   C U E N T A   R E S I D E N C I A L', M, y + 14);

    doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
    doc.text('Cerrada Mixcoac', M, y + 42);

    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text(`Periodo: ${label}`, W - M, y + 10, { align:'right' });
    doc.setTextColor(...PDF.notes);
    doc.text(`Generado: ${generadoEl}`, W - M, y + 22, { align:'right' });
    doc.text(`Folio: ${folio}`, W - M, y + 34, { align:'right' });

    y += 58;
    doc.setDrawColor(...PDF.grid);
    doc.line(M, y, W - M, y);
    y += 24;

    /* ===== 2. Tres cajas de balance ===== */
    const boxGap = 14, boxW = (W - 2*M - 2*boxGap) / 3, boxH = 68;
    const boxes = [
      { label:'TOTAL COBRADO', value: cobrado, color: PDF.green, cmp: cmpCobrado, higherIsBetter:true },
      { label:'GASTOS', value: gastos, color: PDF.red, cmp: cmpGastos, higherIsBetter:false },
      { label:'SALDO EN CAJA', value: saldo, color: PDF.navy, cmp: cmpSaldo, higherIsBetter:true },
    ];
    boxes.forEach((b, i) => {
      const x = M + i*(boxW + boxGap);
      doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
      doc.roundedRect(x, y, boxW, boxH, 6, 6, 'FD');
      doc.setFont('helvetica','bold'); doc.setFontSize(8.5); doc.setTextColor(...PDF.secondary);
      doc.text(b.label, x + 14, y + 20);
      doc.setFont('courier','bold'); doc.setFontSize(16); doc.setTextColor(...b.color);
      doc.text(money(b.value), x + boxW - 14, y + 44, { align:'right' });
      if (b.cmp !== null){
        const up = b.cmp >= 0;
        const good = b.higherIsBetter ? up : !up;
        doc.setFont('helvetica','bold'); doc.setFontSize(8);
        doc.setTextColor(...(good ? PDF.green : PDF.red));
        // ▲▼ evitados a propósito: los fuentes estándar de jsPDF (Helvetica WinAnsi) no
        // los soportan y corrompen la codificación del texto completo. +/- sí es seguro.
        doc.text(`${up?'+':'-'}${Math.abs(b.cmp)}% vs mes anterior`, x + 14, y + 58);
      } else {
        doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(...PDF.notes);
        doc.text('Sin datos del mes anterior', x + 14, y + 58);
      }
    });
    y += boxH + 22;

    /* ===== 3. Indicador de salud financiera ===== */
    y = dibujarSaludFinanciera(doc, W, y, cobrado, gastos);
    y += 10;

    const tituloSeccion = (txt) => {
      doc.setFont('helvetica','bold'); doc.setFontSize(12); doc.setTextColor(...PDF.text);
      doc.text(txt, M, y + 12);
      y += 20;
    };

    /* ===== 4. Barras Ingresos vs Gastos — solo meses con movimientos ===== */
    tituloSeccion('Ingresos vs Gastos');
    const { labels: barLabels, ingresos: barIngresos, gastos: barGastos } = mesesConMovimientos(byMonth);
    const barImg = await renderBarrasHiRes(barLabels, barIngresos, barGastos);
    const barBoxW = W - 2*M, barImgH = 140;
    doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
    doc.roundedRect(M, y, barBoxW, barImgH + 16, 6, 6, 'FD');
    doc.addImage(barImg, 'PNG', M + 8, y + 8, barBoxW - 16, barImgH);
    y += barImgH + 16 + 12;
    y = dibujarLeyendaSeries(doc, W, y, [{ label:'Ingresos', color:'#0f766e' }, { label:'Gastos', color:'#991b1b' }]);
    y += 14;

    /* ===== 5. Dona por categoría (izquierda) + desglose nativo (derecha), mayor a menor ===== */
    tituloSeccion('Distribución de gastos por categoría');
    const catRaw = categoriasDelMes(curKey);
    const order = catRaw.labels.map((l,i)=>i).sort((a,b)=>catRaw.data[b]-catRaw.data[a]);
    const pdfCatLabels = order.map(i=>catRaw.labels[i]);
    const pdfCatData = order.map(i=>catRaw.data[i]);
    const pdfCatHasData = catRaw.hasData;
    const pastelImg = await renderPastelDoughnutHiRes(pdfCatLabels, pdfCatData, pdfCatHasData, money(gastos));
    const donutSize = 150, donutX = M, donutY = y;
    doc.addImage(pastelImg, 'PNG', donutX, donutY, donutSize, donutSize);
    const legendX0 = donutX + donutSize + 24, legendX1 = W - M;
    const legendEnd = dibujarLeyendaCategorias(doc, W, donutY + 6, pdfCatLabels, pdfCatData, pdfCatHasData, legendX0, legendX1);
    y = Math.max(donutY + donutSize + 14, legendEnd) + 10;

    /* ===== 6. Tabla "03 · Historial de transacciones" ===== */
    doc.setFillColor(...PDF.gold); doc.rect(M, y, 20, 3, 'F');
    doc.setFont('helvetica','bold'); doc.setFontSize(12); doc.setTextColor(...PDF.text);
    doc.text('03 · Historial de transacciones', M + 28, y + 6);
    y += 20;

    const rows = monthMovs.map(m => ({
      fecha: fmtTime(m.ts), tipo: m.tipo, categoria: m.categoria || 'Otro', concepto: m.concepto || '', monto: m.monto,
    }));

    doc.autoTable({
      startY: y,
      head: [['Fecha','Categoría','Concepto','Monto']],
      body: rows.length
        // "-" ASCII normal, no "−" (U+2212): ese signo no existe en WinAnsi/Helvetica estándar
        // de jsPDF y corrompe toda la celda (mismo bug que las flechas ▲▼ de las cajas).
        ? rows.map(r => [r.fecha, r.categoria, r.concepto, (r.tipo==='ingreso'?'+':'-') + money(r.monto)])
        : [['—','—','Sin movimientos','—']],
      foot: rows.length ? [['', '', 'Saldo del periodo', (saldo>=0?'+':'-') + money(Math.abs(saldo))]] : [],
      theme:'plain',
      styles:{ font:'helvetica', fontSize:9, textColor: PDF.text, cellPadding:6, lineColor: PDF.grid, lineWidth:0.5 },
      headStyles:{ fillColor:[255,255,255], textColor: PDF.secondary, fontStyle:'bold', fontSize:8.5, lineColor: PDF.text },
      alternateRowStyles:{ fillColor: PDF.zebra },
      columnStyles:{ 3:{ halign:'right', font:'courier', fontStyle:'bold' } },
      margin:{ left:M, right:M, bottom: 50 },
      didParseCell(data){
        if (data.section === 'body' && data.column.index === 1 && rows[data.row.index]){
          data.cell.text = [''];
        }
        if (data.section === 'body' && data.column.index === 3 && rows[data.row.index]){
          data.cell.styles.textColor = rows[data.row.index].tipo === 'ingreso' ? PDF.green : PDF.red;
        }
        if (data.section === 'foot'){
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.textColor = PDF.text;
          if (data.column.index === 3){ data.cell.styles.font = 'courier'; data.cell.styles.halign = 'right'; }
        }
      },
      didDrawCell(data){
        if (data.section === 'body' && data.column.index === 1 && rows[data.row.index]){
          const r = rows[data.row.index];
          const ing = r.tipo === 'ingreso';
          doc.setFont('helvetica','bold'); doc.setFontSize(8);
          const textW = doc.getTextWidth(r.categoria);
          const padX = 6, badgeW = textW + padX*2, badgeH = 14;
          const bx = data.cell.x + 4, by = data.cell.y + (data.cell.height - badgeH) / 2;
          doc.setFillColor(...(ing ? PDF.badgeGreenBg : PDF.badgeRedBg));
          doc.roundedRect(bx, by, badgeW, badgeH, 3, 3, 'F');
          doc.setTextColor(...(ing ? PDF.badgeGreenFg : PDF.badgeRedFg));
          doc.text(r.categoria, bx + padX, by + badgeH/2 + 3);
        }
        if (data.section === 'foot' && data.row.index === 0 && data.column.index === 0){
          doc.setDrawColor(...PDF.text); doc.setLineWidth(0.6);
          doc.line(M, data.cell.y, W - M, data.cell.y);
          doc.line(M, data.cell.y + 2, W - M, data.cell.y + 2);
        }
      },
    });

    /* ===== 7. Pie en todas las páginas =====
       Folio + página van juntos a la derecha (no centrados) para no traslaparse con el texto
       de la izquierda — con folio+fecha+"Reporte financiero oficial..." los tres textos
       independientes no cabían en el ancho de la página. */
    const totalPages = doc.internal.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++){
      doc.setPage(p);
      doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
      doc.text('Reporte financiero oficial · Cerrada Mixcoac · Transparencia vecinal', M, H - 24);
      doc.text(`${folio} · Página ${p} de ${totalPages}`, W - M, H - 24, { align:'right' });
    }

    return { doc, filename: `Finanzas-Mixcoac-${label.replace(' ','-')}.pdf` };
}

/* botón "Reporte PDF": solo descarga */
async function generarPDF(){
  const btn = $('#pdfBtn'); const btnLabel = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = await construirReportePDF();
    doc.save(filename);
  } catch(e){
    console.error('generarPDF', e);
    toast('No se pudo generar el PDF', 'bad');
  } finally {
    btn.disabled = false; btn.textContent = btnLabel;
  }
}

/* botón "Compartir reporte": Web Share API nivel 2 (con archivo) para elegir WhatsApp directo
   desde el panel nativo del celular; en escritorio o sin soporte, descarga y avisa.
   Nada de awaits innecesarios entre terminar el PDF y llamar a navigator.share(): algunos
   navegadores móviles invalidan el "gesto de usuario" si se demora demasiado o se anida mal. */
async function compartirReportePDF(){
  const btn = $('#waBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = await construirReportePDF();
    const blob = doc.output('blob');
    const file = new File([blob], filename, { type: 'application/pdf' });

    if (navigator.canShare && navigator.canShare({ files: [file] })){
      await navigator.share({ files: [file], title: 'Reporte financiero · Cerrada Mixcoac' });
      toast('Reporte compartido', 'ok');
    } else {
      doc.save(filename);
      toast('PDF descargado — adjúntalo en WhatsApp', 'ok');
    }
  } catch(e){
    if (e && e.name === 'AbortError'){
      // el usuario cerró el panel de compartir sin elegir nada; no es un error real.
    } else {
      console.error('compartirReportePDF', e);
      toast('No se pudo generar el reporte', 'bad');
    }
  } finally {
    btn.disabled = false; btn.textContent = original;
  }
}
$('#waBtn').addEventListener('click', compartirReportePDF);

/* ====================== FASE 4.5 · RECIBOS DE PAGO ====================== */
function tsADate(ts){ return ts && ts.toDate ? ts.toDate() : new Date(ts); }

/* Recibo individual, una página carta, misma identidad tipográfica de FASE 0
   (filete dorado, eyebrow espaciado, folio a la derecha, montos en courier). */
function construirReciboPDF(mov){
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'pt', format:'letter' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = PDF.MARGIN;
  const fecha = tsADate(mov.ts).toLocaleString('es-MX', { day:'2-digit', month:'long', year:'numeric', hour:'2-digit', minute:'2-digit' });

  doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');
  let y = M - 10;
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('R E C I B O   D E   P A G O', M, y + 14);
  doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
  doc.text('Cerrada Mixcoac', M, y + 42);
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text(`Folio: ${mov.folioRecibo}`, W - M, y + 10, { align:'right' });
  doc.setTextColor(...PDF.notes);
  doc.text(`Emitido: ${fecha}`, W - M, y + 22, { align:'right' });

  y += 58; doc.setDrawColor(...PDF.grid); doc.line(M, y, W - M, y); y += 30;

  const boxH = 88;
  doc.setDrawColor(...PDF.grid); doc.setFillColor(255,255,255);
  doc.roundedRect(M, y, W - 2*M, boxH, 8, 8, 'FD');
  doc.setFont('helvetica','bold'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('MONTO RECIBIDO', M + 18, y + 24);
  doc.setFont('courier','bold'); doc.setFontSize(30); doc.setTextColor(...PDF.green);
  doc.text(money(mov.monto), W - M - 18, y + 58, { align:'right' });
  y += boxH + 34;

  const filas = [
    ['CASA', mov.casa || '—'],
    ['CONCEPTO', mov.concepto || '—'],
    ['CATEGORÍA', mov.categoria || 'Otro'],
    ['FECHA Y HORA', fecha],
    ['REGISTRÓ', mov.creadoNombre || '—'],
  ];
  filas.forEach(([k, v]) => {
    doc.setFont('helvetica','bold'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
    doc.text(k, M, y);
    doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(...PDF.text);
    doc.text(String(v).slice(0, 90), M + 140, y);
    doc.setDrawColor(...PDF.grid); doc.setLineWidth(0.5);
    doc.line(M, y + 8, W - M, y + 8);
    y += 28;
  });

  doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
  doc.text('Recibo oficial · Cerrada Mixcoac · Transparencia vecinal', M, H - 24);
  doc.text(`${mov.folioRecibo} · Página 1 de 1`, W - M, H - 24, { align:'right' });

  return { doc, filename: `Recibo-${mov.folioRecibo}.pdf` };
}

let reciboActual = null;
function abrirReciboSheet(mov){
  reciboActual = mov;
  $('#reciboTitle').textContent = `Recibo ${mov.folioRecibo}`;
  $('#reciboErr').textContent = '';
  $('#reciboDatos').innerHTML =
    `<b>${esc(mov.casa || '—')}</b> · ${esc(mov.concepto || '')}<br>` +
    `${esc(mov.categoria || 'Otro')} · ${money(mov.monto)} · ${fmtTime(mov.ts)}`;
  openSheet('#reciboOverlay');
}
$('#reciboOverlay').addEventListener('click', e => { if (e.target.id==='reciboOverlay') closeSheet('#reciboOverlay'); });

/* Marca envío/descarga en el movimiento (vía Worker). Si falla no bloquea:
   el recibo ya salió; solo se avisa que la marca no quedó registrada. */
async function marcarReciboEnviado(id, accion){
  try { await authedFetch('/finanzas/marcar-recibo', { id, accion }); }
  catch(e){ console.error('marcarRecibo', e); toast('Recibo ok, pero no se registró el envío', 'bad'); }
}

/* Compartir por WhatsApp: Web Share nivel 2, mismo patrón FASE 1 — sin awaits entre
   generar el PDF y navigator.share() para no perder el gesto de usuario en móviles. */
$('#reciboWaBtn').addEventListener('click', async () => {
  const mov = reciboActual; if (!mov) return;
  const btn = $('#reciboWaBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = construirReciboPDF(mov);
    const file = new File([doc.output('blob')], filename, { type:'application/pdf' });
    if (navigator.canShare && navigator.canShare({ files:[file] })){
      await navigator.share({ files:[file], title:`Recibo ${mov.folioRecibo} · Cerrada Mixcoac` });
      toast('Recibo compartido', 'ok');
      await marcarReciboEnviado(mov.id, 'compartido');
    } else {
      doc.save(filename);
      toast('PDF descargado — adjúntalo en WhatsApp', 'ok');
      await marcarReciboEnviado(mov.id, 'descargado');
    }
  } catch(e){
    if (e && e.name === 'AbortError'){
      // el usuario cerró el panel de compartir; no es un error real.
    } else {
      console.error('compartirRecibo', e);
      $('#reciboErr').textContent = 'No se pudo generar el recibo';
    }
  } finally { btn.disabled = false; btn.textContent = original; }
});

/* Plan B siempre visible: descarga directa (Web Share falla a veces en iOS). */
$('#reciboDlBtn').addEventListener('click', async () => {
  const mov = reciboActual; if (!mov) return;
  const btn = $('#reciboDlBtn'); const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generando…';
  try {
    const { doc, filename } = construirReciboPDF(mov);
    doc.save(filename);
    toast('Recibo descargado', 'ok');
    await marcarReciboEnviado(mov.id, 'descargado');
  } catch(e){
    console.error('descargarRecibo', e);
    $('#reciboErr').textContent = 'No se pudo generar el recibo';
  } finally { btn.disabled = false; btn.textContent = original; }
});

/* ====================== FASE 4.5 · REPORTE POR CASA (FASE 5: desde el padrón) ====================== */
$('#casaRepBtn').addEventListener('click', () => {
  const casas = vecinosCache.slice()
    .sort((a,b) => a.domicilio.localeCompare(b.domicilio, 'es', { numeric:true }))
    .map(v => v.domicilio);
  const sel = $('#casaRepSel');
  sel.innerHTML = '';
  if (!casas.length){ sel.appendChild(new Option('Sin vecinos en el padrón','')); }
  else { sel.appendChild(new Option('Elige un domicilio…','')); casas.forEach(c => sel.appendChild(new Option(c, c))); }
  $('#casaRepCustomField').classList.add('hidden');   // ya no hay texto libre: el padrón es la fuente
  $('#casaRepErr').textContent = '';
  openSheet('#casaRepOverlay');
});
$('#casaRepOverlay').addEventListener('click', e => { if (e.target.id==='casaRepOverlay') closeSheet('#casaRepOverlay'); });

$('#casaRepGo').addEventListener('click', async () => {
  const casa = $('#casaRepSel').value;
  if (!casa){ $('#casaRepErr').textContent = 'Elige un domicilio'; return; }
  const btn = $('#casaRepGo'); btn.disabled = true; btn.textContent = 'Generando…';
  try {
    // Historial completo de la casa (no solo los 6 meses del cache). Sin orderBy
    // encadenado al where para no requerir índice compuesto — se ordena aquí.
    const snap = await db.collection('finanzas').where('casa','==',casa).get();
    const movs = snap.docs.map(d => ({ id: d.id, ...d.data() }))
      .filter(m => m.tipo === 'ingreso')
      .sort((a,b) => tsADate(b.ts) - tsADate(a.ts));
    if (!movs.length){ $('#casaRepErr').textContent = `Sin pagos registrados para "${casa}"`; return; }
    const { doc, filename } = construirReporteCasaPDF(casa, movs);
    doc.save(filename);
    toast('Reporte descargado', 'ok');
    closeSheet('#casaRepOverlay');
  } catch(e){
    console.error('reporteCasa', e);
    $('#casaRepErr').textContent = 'No se pudo generar el reporte';
  } finally { btn.disabled = false; btn.textContent = 'Generar PDF'; }
});

/* Historial de pagos de una casa, identidad FASE 0. Cada pago referencia su folio
   de recibo y la fecha de envío/descarga — el soporte para aclaraciones. */
function construirReporteCasaPDF(casa, movs){
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'pt', format:'letter' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = PDF.MARGIN;
  const generadoEl = new Date().toLocaleString('es-MX', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
  const total = movs.reduce((a,m) => a + (m.monto || 0), 0);

  doc.setFillColor(...PDF.gold); doc.rect(0, 0, W, 4, 'F');
  let y = M - 10;
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text('H I S T O R I A L   D E   P A G O S', M, y + 14);
  doc.setFont('helvetica','bold'); doc.setFontSize(26); doc.setTextColor(...PDF.text);
  doc.text('Cerrada Mixcoac', M, y + 42);
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(...PDF.secondary);
  doc.text(`Casa: ${casa}`, W - M, y + 10, { align:'right' });
  doc.setTextColor(...PDF.notes);
  doc.text(`Generado: ${generadoEl}`, W - M, y + 22, { align:'right' });
  doc.text(`${movs.length} pago(s)`, W - M, y + 34, { align:'right' });

  y += 58; doc.setDrawColor(...PDF.grid); doc.line(M, y, W - M, y); y += 24;

  const fmtEnvio = m => {
    const ts = m.reciboCompartidoTs || m.reciboDescargadoTs;
    if (!ts) return '—';
    const cuando = tsADate(ts).toLocaleString('es-MX', { day:'2-digit', month:'short', year:'2-digit', hour:'2-digit', minute:'2-digit' });
    return (m.reciboCompartidoTs ? 'Enviado ' : 'Descargado ') + cuando;
  };

  doc.autoTable({
    startY: y,
    head: [['Fecha','Concepto','Categoría','Folio recibo','Recibo enviado','Monto']],
    body: movs.map(m => [
      fmtTime(m.ts),
      (m.concepto || '—').slice(0, 40),
      m.categoria || 'Otro',
      m.folioRecibo || '—',
      fmtEnvio(m),
      '+' + money(m.monto),
    ]),
    foot: [['', '', '', '', 'Total pagado', '+' + money(total)]],
    theme:'plain',
    styles:{ font:'helvetica', fontSize:8.5, textColor: PDF.text, cellPadding:6, lineColor: PDF.grid, lineWidth:0.5 },
    headStyles:{ fillColor:[255,255,255], textColor: PDF.secondary, fontStyle:'bold', fontSize:8, lineColor: PDF.text },
    alternateRowStyles:{ fillColor: PDF.zebra },
    columnStyles:{ 3:{ font:'courier' }, 5:{ halign:'right', font:'courier', fontStyle:'bold', textColor: PDF.green } },
    margin:{ left:M, right:M, bottom: 50 },
    didParseCell(data){
      if (data.section === 'foot'){
        data.cell.styles.fontStyle = 'bold';
        data.cell.styles.textColor = PDF.text;
        if (data.column.index === 5){ data.cell.styles.font = 'courier'; data.cell.styles.halign = 'right'; }
      }
    },
    didDrawCell(data){
      if (data.section === 'foot' && data.row.index === 0 && data.column.index === 0){
        doc.setDrawColor(...PDF.text); doc.setLineWidth(0.6);
        doc.line(M, data.cell.y, W - M, data.cell.y);
        doc.line(M, data.cell.y + 2, W - M, data.cell.y + 2);
      }
    },
  });

  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++){
    doc.setPage(p);
    doc.setFont('helvetica','normal'); doc.setFontSize(7); doc.setTextColor(...PDF.notes);
    doc.text('Historial de pagos oficial · Cerrada Mixcoac · Transparencia vecinal', M, H - 24);
    doc.text(`${casa} · Página ${p} de ${totalPages}`, W - M, H - 24, { align:'right' });
  }

  return { doc, filename: `Pagos-${casa.replace(/\s+/g,'-')}-Mixcoac.pdf` };
}

function openSheet(sel){ $(sel).classList.add('open'); }
function closeSheet(sel){ $(sel).classList.remove('open'); }

/* ====================== PUSH (FCM) ====================== */
async function registerPush(){
  // Solo residentes reciben push (de sus esclavos/visitantes).
  if (ME.rol!=='residente') return;
  try {
    if (!('serviceWorker' in navigator) || !firebase.messaging.isSupported()) return;
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return;
    const reg = await navigator.serviceWorker.register('firebase-messaging-sw.js');
    const messaging = firebase.messaging();
    const token = await messaging.getToken({ vapidKey: CONFIG.vapidKey, serviceWorkerRegistration: reg });
    if (token){
      await db.collection('usuarios').doc(ME.uid).set({ fcmToken: token }, { merge:true });
    }
    messaging.onMessage(p => toast(p.notification?.body || 'Movimiento en tu hogar'));
  } catch(e){ console.warn('Push no disponible', e); }
}

/* ====================== Service worker (PWA) ====================== */
if ('serviceWorker' in navigator){
  window.addEventListener('load', ()=> navigator.serviceWorker.register('sw.js').catch(()=>{}));
}
