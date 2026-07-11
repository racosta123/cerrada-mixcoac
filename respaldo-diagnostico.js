/* ===========================================================
   Respaldo + diagnóstico de la colección "finanzas", de SOLO LECTURA.
   Este script NUNCA escribe ni borra nada en Firestore — solo lee
   y guarda una copia local en JSON. Pensado para correr ANTES de
   migrar-categorias.js, para poder revisar y restaurar si algo sale mal.

   Genera:
     1) ./backups/finanzas-<timestamp>.json   — respaldo completo (todos los campos)
     2) En consola: listado completo de movimientos (id, fecha, categoría, concepto, monto)
     3) En consola: el mismo dry-run que mostraría migrar-categorias.js
        (usa el mismo categorias-map.js, así que es exactamente el mismo cálculo)

   Uso:
     node respaldo-diagnostico.js

   Requiere las mismas variables de entorno que migrar-categorias.js:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   =========================================================== */

const fs = require('fs');
const path = require('path');

const { normalizar } = require('./categorias-map');
const { saToken, listCollection, fsDocToPlain } = require('./firestore-sa');

function timestampParaArchivo(){
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function fmtFecha(ts){
  if (!ts) return '(sin fecha)';
  const d = new Date(ts);
  return isNaN(d) ? String(ts) : d.toLocaleString('es-MX', { dateStyle: 'medium', timeStyle: 'short' });
}

function fmtMonto(m){
  return typeof m === 'number' ? m.toLocaleString('es-MX', { style: 'currency', currency: 'MXN' }) : String(m);
}

async function main(){
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}. Ver instrucciones al inicio del archivo.`); process.exit(1); }
  }

  console.log('🔎 Respaldo + diagnóstico de "finanzas" (solo lectura, no se escribe nada en Firestore).');
  console.log('');

  const token = await saToken(); // scope readonly, por defecto — este script nunca escribe
  const docsRaw = await listCollection(token, 'finanzas');
  const movimientos = docsRaw.map(fsDocToPlain).sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));

  console.log(`Documentos en "finanzas": ${movimientos.length}`);
  console.log('');

  // 1) Respaldo completo a JSON local
  const backupDir = path.join(__dirname, 'backups');
  fs.mkdirSync(backupDir, { recursive: true });
  const backupPath = path.join(backupDir, `finanzas-${timestampParaArchivo()}.json`);
  fs.writeFileSync(backupPath, JSON.stringify({
    exportadoEn: new Date().toISOString(),
    proyecto: process.env.FIREBASE_PROJECT,
    coleccion: 'finanzas',
    total: movimientos.length,
    documentos: movimientos,
  }, null, 2), 'utf8');
  console.log(`✅ Respaldo guardado en: ${backupPath}`);
  console.log('');

  // 2) Listado completo, para identificar datos de prueba a mano
  console.log('=== Listado completo de movimientos ===');
  console.log('');
  movimientos.forEach(m => {
    console.log(`${m.id}  |  ${fmtFecha(m.ts)}  |  ${m.tipo || '(sin tipo)'}  |  ${m.categoria || '(sin categoría)'}  |  ${m.concepto || '(sin concepto)'}  |  ${fmtMonto(m.monto)}`);
  });
  console.log('');
  console.log(`Total: ${movimientos.length} movimiento(s).`);
  console.log('');

  // 3) Dry-run de la migración de categorías (mismo cálculo que migrar-categorias.js)
  console.log('=== Dry-run de migración de categorías ===');
  console.log('');
  const cambios = [];
  const sinReconocer = new Set();
  movimientos.forEach(m => {
    const categoriaActual = m.categoria || '';
    const nueva = normalizar(categoriaActual);
    if (nueva === null) return; // ya está bien
    if (nueva === undefined) { sinReconocer.add(categoriaActual); return; }
    cambios.push({ id: m.id, de: categoriaActual, a: nueva });
  });

  console.log(`Cambios que la migración aplicaría: ${cambios.length}`);
  cambios.forEach(c => console.log(`  ${c.id}:  "${c.de}"  →  "${c.a}"`));

  if (sinReconocer.size){
    console.log('');
    console.log('⚠️  Categorías sin mapeo conocido (la migración NO las toca, revisar a mano):');
    [...sinReconocer].forEach(c => console.log(`  "${c}"`));
  }

  console.log('');
  console.log('Nada se escribió en Firestore. Este script es solo de lectura.');
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
