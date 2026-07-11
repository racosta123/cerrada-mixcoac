/* ===========================================================
   Publica el firestore.rules LOCAL como reglas activas del proyecto
   (equivalente a pegarlas en la consola de Firebase y dar "Publicar").

   Crea un ruleset nuevo con el contenido de ./firestore.rules y apunta
   el release cloud.firestore a él. El ruleset anterior queda en el
   historial de la consola por si hay que revertir.

   Uso:
     node publicar-reglas.js

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
  const source = fs.readFileSync('./firestore.rules', 'utf8');
  if (!/match\s*\/config\//.test(source)) {
    console.error('El firestore.rules local no tiene el bloque /config — ¿estás en la carpeta correcta?');
    process.exit(1);
  }
  const token = await saToken('https://www.googleapis.com/auth/firebase');
  const H = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };

  // 1) crear el ruleset con la fuente local
  const rsR = await fetch(`https://firebaserules.googleapis.com/v1/projects/${proj}/rulesets`, {
    method: 'POST', headers: H,
    body: JSON.stringify({ source: { files: [{ name: 'firestore.rules', content: source }] } }),
  });
  if (!rsR.ok) throw new Error('No se pudo crear el ruleset (¿error de sintaxis en las reglas?): ' + rsR.status + ' ' + await rsR.text());
  const rs = await rsR.json();
  console.log('Ruleset creado :', rs.name);

  // 2) apuntar el release activo al ruleset nuevo
  const relName = `projects/${proj}/releases/cloud.firestore`;
  const relR = await fetch(`https://firebaserules.googleapis.com/v1/${relName}`, {
    method: 'PATCH', headers: H,
    body: JSON.stringify({ release: { name: relName, rulesetName: rs.name } }),
  });
  if (!relR.ok) throw new Error('No se pudo actualizar el release: ' + relR.status + ' ' + await relR.text());
  const rel = await relR.json();
  console.log('Release activo :', rel.rulesetName);
  console.log('✅ Reglas publicadas. La lectura de config/general para staff queda habilitada.');
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
