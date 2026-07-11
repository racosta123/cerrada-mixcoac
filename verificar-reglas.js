/* ===========================================================
   Diagnóstico de BUG 1 (FASE 4): ¿las reglas de Firestore DESPLEGADAS
   permiten leer config/general al staff?

   Descarga el ruleset activo (release cloud.firestore) vía la API de
   Firebase Rules y reporta si contiene el bloque `match /config/`.
   SOLO LECTURA — no modifica nada.

   Uso:
     node verificar-reglas.js

   Requiere las mismas variables de entorno que los otros scripts:
     FIREBASE_PROJECT, SA_EMAIL, SA_PRIVATE_KEY
   =========================================================== */

const fs = require('fs');
const { saToken } = require('./firestore-sa');

async function main(){
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}.`); process.exit(1); }
  }
  const proj = process.env.FIREBASE_PROJECT;
  const token = await saToken('https://www.googleapis.com/auth/firebase');
  const H = { Authorization: 'Bearer ' + token };

  // 1) release activo de Firestore
  const relUrl = `https://firebaserules.googleapis.com/v1/projects/${proj}/releases/cloud.firestore`;
  const relR = await fetch(relUrl, { headers: H });
  if (!relR.ok) throw new Error('No se pudo leer el release: ' + relR.status + ' ' + await relR.text());
  const rel = await relR.json();
  console.log('Release activo :', rel.name);
  console.log('Ruleset activo :', rel.rulesetName);
  console.log('Actualizado    :', rel.updateTime);

  // 2) fuente del ruleset activo
  const rsR = await fetch(`https://firebaserules.googleapis.com/v1/${rel.rulesetName}`, { headers: H });
  if (!rsR.ok) throw new Error('No se pudo leer el ruleset: ' + rsR.status + ' ' + await rsR.text());
  const rs = await rsR.json();
  const desplegadas = (rs.source.files || []).map(f => f.content).join('\n');

  // 3) comparación con el archivo local
  const locales = fs.readFileSync('./firestore.rules', 'utf8');
  const tieneConfig = /match\s*\/config\//.test(desplegadas);
  const igualALocal = desplegadas.replace(/\s+/g,' ').trim() === locales.replace(/\s+/g,' ').trim();

  console.log('');
  console.log(tieneConfig
    ? '✅ Las reglas DESPLEGADAS sí tienen el bloque match /config/ — la lectura de config/general NO está bloqueada por reglas.'
    : '❌ Las reglas DESPLEGADAS NO tienen ningún bloque match /config/ → toda lectura de config/general es DENEGADA (permission-denied), incluso para master/admin. Esta es la causa raíz del BUG 1.');
  console.log(igualALocal
    ? '✅ Coinciden con el firestore.rules local.'
    : '⚠️  NO coinciden con el firestore.rules local (el local aún no se publica). Usa: node publicar-reglas.js');

  console.log('\n----- reglas desplegadas (fuente completa) -----\n');
  console.log(desplegadas);
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
