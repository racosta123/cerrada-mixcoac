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
  if (isStaff) loadUsers();
}

function switchTab(id, btn){
  $$('.tabpane').forEach(p => p.classList.add('hidden'));
  $('#tab-'+id).classList.remove('hidden');
  $$('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
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
    const sentido = a.puerta==='salida' ? 'out' : 'in';
    const row = document.createElement('div');
    row.className = 'row';
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
    snap.forEach(doc => {
      if (doc.id === ME.uid) return;
      const u = doc.data();
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
      row.innerHTML = `
        <div class="ri">${(u.nombre||'?')[0].toUpperCase()}</div>
        <div class="rt"><div class="a">${esc(u.nombre)}</div><div class="b">${esc(u.email||'')} ${u.casa?'· '+esc(u.casa):''}</div></div>
        <div style="display:flex;gap:8px;align-items:center">${right}</div>`;
      list.appendChild(row);
    });
    list.querySelectorAll('[data-susp]').forEach(b=> b.onclick=()=> toggleSuspender(b.dataset.susp, true, b));
    list.querySelectorAll('[data-react]').forEach(b=> b.onclick=()=> toggleSuspender(b.dataset.react, false, b));
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

/* ====================== FINANZAS ====================== */
let movType = 'ingreso';
let finCache = [];

function monthRange(){
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 1);
  const end = new Date(now.getFullYear(), now.getMonth()+1, 1);
  return { start, end, label: now.toLocaleDateString('es-MX',{month:'long',year:'numeric'}) };
}
const money = n => '$'+(n||0).toLocaleString('es-MX',{minimumFractionDigits:0,maximumFractionDigits:2});

function watchFinanzas(){
  if (unsubFin) unsubFin();
  const isStaff = (ME.rol==='master' || ME.rol==='admin');
  // Solo staff registra; residentes/esclavos ven en modo lectura.
  $('#newMovBtn').style.display = isStaff ? 'block' : 'none';

  const { start, end, label } = monthRange();
  $('#finMonth').textContent = 'Finanzas · ' + label;
  unsubFin = db.collection('finanzas')
    .where('ts','>=',start).where('ts','<',end)
    .orderBy('ts','desc').limit(300)
    .onSnapshot(snap => {
      finCache = [];
      let cobrado = 0, gastos = 0;
      snap.forEach(doc => {
        const m = doc.data(); finCache.push(m);
        if (m.tipo==='ingreso') cobrado += m.monto; else gastos += m.monto;
      });
      $('#finCobrado').textContent = money(cobrado);
      $('#finGastos').textContent = money(gastos);
      $('#finCaja').textContent = money(cobrado - gastos);
      renderMovs(snap);
    }, err => { console.error(err); $('#movList').innerHTML='<div class="empty">Sin acceso a finanzas</div>'; });
}

function renderMovs(snap){
  const list = $('#movList');
  if (snap.empty){ list.innerHTML = '<div class="empty">Sin movimientos este mes</div>'; return; }
  list.innerHTML = '';
  snap.forEach(doc => {
    const m = doc.data();
    const ing = m.tipo==='ingreso';
    const row = document.createElement('div'); row.className = 'row';
    row.innerHTML = `
      <div class="ri"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ing?'<path d="M12 19V5 M5 12l7-7 7 7"/>':'<path d="M12 5v14 M19 12l-7 7-7-7"/>'}</svg></div>
      <div class="rt"><div class="a">${esc(m.concepto||m.categoria)}</div><div class="b">${esc(m.categoria)} · ${fmtTime(m.ts)}</div></div>
      <span class="mov-amt ${ing?'ok':'bad'}">${ing?'+':'−'}${money(m.monto)}</span>`;
    list.appendChild(row);
  });
}

/* registrar movimiento (solo staff) */
$('#newMovBtn').addEventListener('click', ()=>{ $('#movErr').textContent=''; openSheet('#movOverlay'); });
$('#movOverlay').addEventListener('click', e => { if(e.target.id==='movOverlay') closeSheet('#movOverlay'); });
$('#movTypeSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if(!b) return;
  $$('#movTypeSeg button').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); movType = b.dataset.t;
});
$('#saveMovBtn').addEventListener('click', saveMov);

async function saveMov(){
  const concepto = $('#movConcept').value.trim();
  const categoria = $('#movCat').value.trim() || 'Otro';
  const monto = parseFloat($('#movAmount').value);
  $('#movErr').textContent = '';
  if (!concepto || !(monto > 0)){ $('#movErr').textContent = 'Falta concepto o monto válido'; return; }
  const btn = $('#saveMovBtn'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    // El movimiento lo escribe el Worker tras verificar rol master/admin.
    await authedFetch('/finanzas/registrar', { tipo: movType, concepto, categoria, monto });
    toast('Movimiento registrado', 'ok');
    closeSheet('#movOverlay');
    $('#movConcept').value = $('#movCat').value = $('#movAmount').value = '';
  } catch(e){ $('#movErr').textContent = e.message || 'No se pudo guardar'; }
  finally { btn.disabled = false; btn.textContent = 'Guardar movimiento'; }
}

/* reporte PDF para el grupo de residentes */
$('#pdfBtn').addEventListener('click', generarPDF);

function generarPDF(){
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit:'pt', format:'a4' });
  const W = doc.internal.pageSize.getWidth();
  const { label } = monthRange();
  const gold = [184,148,31], green=[34,160,110], red=[200,70,70], dark=[20,20,23];

  // Encabezado
  doc.setFillColor(...dark); doc.rect(0,0,W,90,'F');
  doc.setFillColor(...gold); doc.roundedRect(40,28,34,34,8,8,'F');
  doc.setTextColor(255); doc.setFont('helvetica','bold'); doc.setFontSize(18);
  doc.text('Cerrada Mixcoac', 88, 46);
  doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(200);
  doc.text('Reporte de finanzas · '+label, 88, 64);

  let cobrado=0, gastos=0;
  finCache.forEach(m => m.tipo==='ingreso' ? cobrado+=m.monto : gastos+=m.monto);

  // Tarjetas resumen
  const cy = 120, cw=(W-80-24)/3;
  const cards = [['Cobrado',money(cobrado),green],['Gastos',money(gastos),red],['En caja',money(cobrado-gastos),gold]];
  cards.forEach((c,i)=>{
    const x = 40 + i*(cw+12);
    doc.setDrawColor(225); doc.setFillColor(250,250,250);
    doc.roundedRect(x,cy,cw,64,8,8,'FD');
    doc.setFontSize(9); doc.setTextColor(120); doc.text(c[0], x+12, cy+22);
    doc.setFont('helvetica','bold'); doc.setFontSize(15); doc.setTextColor(...c[2]);
    doc.text(c[1], x+12, cy+46); doc.setFont('helvetica','normal');
  });

  // Tabla de movimientos
  const rows = finCache.map(m => [
    fmtTime(m.ts), m.tipo==='ingreso'?'Ingreso':'Gasto', m.categoria||'', m.concepto||'',
    (m.tipo==='ingreso'?'+':'−')+money(m.monto)
  ]);
  doc.autoTable({
    startY: 208,
    head: [['Fecha','Tipo','Categoría','Concepto','Monto']],
    body: rows.length?rows:[['—','—','—','Sin movimientos','—']],
    theme:'striped',
    headStyles:{ fillColor:dark, textColor:255, fontSize:10 },
    bodyStyles:{ fontSize:9, textColor:40 },
    alternateRowStyles:{ fillColor:[248,248,248] },
    columnStyles:{ 4:{ halign:'right', fontStyle:'bold' } },
    margin:{ left:40, right:40 },
  });

  const fy = doc.lastAutoTable.finalY + 24;
  doc.setFontSize(9); doc.setTextColor(150);
  doc.text('Generado el '+new Date().toLocaleString('es-MX')+' · Cerrada Mixcoac', 40, fy);

  doc.save(`Finanzas-Mixcoac-${label.replace(' ','-')}.pdf`);
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
