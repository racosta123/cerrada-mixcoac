/* ===========================================================
   Siembra config/general.totalCasas ANTES del primer movimiento real (FASE 4).
   Escribe UNA vez (o las veces que se necesite — simplemente sobreescribe el
   campo). NO toca "finanzas" ni ninguna otra colección.

   Uso:
     node sembrar-config.js <totalCasas>

   Requiere las mismas variables de entorno que los otros scripts:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   =========================================================== */

const { saToken } = require('./firestore-sa');

const totalCasas = Number(process.argv[2]);

async function main(){
  if (!Number.isInteger(totalCasas) || totalCasas <= 0) {
    console.error('Uso: node sembrar-config.js <totalCasas>');
    process.exit(1);
  }
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}.`); process.exit(1); }
  }

  const token = await saToken('https://www.googleapis.com/auth/datastore');
  const url = `https://firestore.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT}/databases/(default)/documents/config/general?updateMask.fieldPaths=totalCasas`;
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { totalCasas: { integerValue: totalCasas } } }),
  });
  if (!r.ok) throw new Error('Firestore set falló: ' + r.status + ' ' + await r.text());
  console.log(`✅ config/general.totalCasas = ${totalCasas}`);
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
