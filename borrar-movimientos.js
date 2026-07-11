/* ===========================================================
   Borrado de movimientos en "finanzas", a partir de un respaldo ya
   generado por respaldo-diagnostico.js.

   ⚠️  NO SE EJECUTA AUTOMÁTICAMENTE. Requiere --execute explícito.

   Este script SOLO borra los documentos cuyos IDs aparecen en el
   archivo de respaldo indicado — nunca "todo lo que haya en la
   colección al momento de correr". Así, si alguien lo corre por
   error más adelante (ya con datos reales cargados), no toca nada
   que no estuviera en ese respaldo puntual.

   Uso:
     node borrar-movimientos.js <ruta-al-backup.json>            # dry-run
     node borrar-movimientos.js <ruta-al-backup.json> --execute  # borra de verdad

   Requiere las mismas variables de entorno que los otros scripts:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   =========================================================== */

const fs = require('fs');
const { saToken } = require('./firestore-sa');

const EXECUTE = process.argv.includes('--execute');
const backupPath = process.argv[2];

async function borrarDoc(token, docName){
  const url = `https://firestore.googleapis.com/v1/${docName}`;
  const r = await fetch(url, { method: 'DELETE', headers: { Authorization: 'Bearer ' + token } });
  if (!r.ok) throw new Error('Firestore delete falló: ' + r.status + ' ' + await r.text());
}

async function main(){
  if (!backupPath || !fs.existsSync(backupPath)) {
    console.error('Uso: node borrar-movimientos.js <ruta-al-backup.json> [--execute]');
    process.exit(1);
  }
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}. Ver instrucciones al inicio del archivo.`); process.exit(1); }
  }

  const backup = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  const docs = backup.documentos || [];

  if (backup.proyecto !== process.env.FIREBASE_PROJECT) {
    console.error(`El respaldo es del proyecto "${backup.proyecto}" pero FIREBASE_PROJECT="${process.env.FIREBASE_PROJECT}". Abortando por seguridad.`);
    process.exit(1);
  }

  console.log(EXECUTE ? '⚠️  MODO EJECUCIÓN — se van a BORRAR documentos de Firestore.' : '🔎 MODO DRY-RUN — solo se muestra qué se borraría, no se borra nada.');
  console.log(`Respaldo usado: ${backupPath}`);
  console.log(`Documentos a borrar: ${docs.length}`);
  console.log('');
  docs.forEach(d => console.log(`  ${d.id}  |  ${d.categoria || '(sin categoría)'}  |  ${d.concepto || '(sin concepto)'}  |  ${d.monto ?? ''}`));

  if (!EXECUTE) {
    console.log('');
    console.log('Dry-run terminado. Nada se borró. Para aplicar de verdad: node borrar-movimientos.js "' + backupPath + '" --execute');
    return;
  }

  console.log('');
  console.log('Borrando...');
  const token = await saToken();
  for (const d of docs) {
    await borrarDoc(token, `projects/${backup.proyecto}/databases/(default)/documents/finanzas/${d.id}`);
    console.log(`  ✓ ${d.id} borrado`);
  }
  console.log(`Listo. ${docs.length} documento(s) borrado(s) de Firestore.`);
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
