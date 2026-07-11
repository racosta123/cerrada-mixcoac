/* ===========================================================
   Migración de categorías de "finanzas" a la lista fija normalizada
   (Cuota, Multa, Mantenimiento, Seguridad, Mejoras, Otro).

   ⚠️  NO EJECUTAR SIN AUTORIZACIÓN EXPLÍCITA DEL DUEÑO DEL PROYECTO.
   Este script queda listo pero jamás se corre automáticamente.

   Por defecto corre en modo DRY-RUN: solo imprime qué cambiaría,
   no escribe nada en Firestore. Para escribir de verdad hace falta
   el flag --execute explícito, a propósito, para que sea imposible
   correrlo "por accidente".

   Uso:
     node migrar-categorias.js                # dry-run (no escribe nada)
     node migrar-categorias.js --execute       # aplica los cambios de verdad

   Requiere estas variables de entorno (las mismas credenciales de la
   service account que usa el Worker — NUNCA las pongas en este archivo):
     FIREBASE_PROJECT   ej. cerrada-mixcoac
     SA_EMAIL            email de la service account
     SA_PRIVATE_KEY      clave privada PEM (con \n escapados está bien)

   PowerShell, ejemplo:
     $env:FIREBASE_PROJECT="cerrada-mixcoac"
     $env:SA_EMAIL="...@....iam.gserviceaccount.com"
     $env:SA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
     node migrar-categorias.js
   =========================================================== */

const EXECUTE = process.argv.includes('--execute');

const { normalizar } = require('./categorias-map');
const { saToken, listCollection } = require('./firestore-sa');

async function listarFinanzas(token){
  return listCollection(token, 'finanzas');
}

async function actualizarCategoria(token, docName, nuevaCategoria){
  // docName ya viene como ruta completa ("projects/.../documents/finanzas/xxxx")
  const url = `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=categoria`;
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { categoria: { stringValue: nuevaCategoria } } }),
  });
  if (!r.ok) throw new Error('Firestore update falló: ' + r.status + ' ' + await r.text());
}

async function main(){
  for (const v of ['FIREBASE_PROJECT', 'SA_EMAIL', 'SA_PRIVATE_KEY']){
    if (!process.env[v]) { console.error(`Falta la variable de entorno ${v}. Ver instrucciones al inicio del archivo.`); process.exit(1); }
  }

  console.log(EXECUTE ? '⚠️  MODO EJECUCIÓN — se van a escribir cambios en Firestore.' : '🔎 MODO DRY-RUN — solo se muestra qué cambiaría, no se escribe nada.');
  console.log('');

  // Scope de escritura explícito: este script sí necesita poder hacer PATCH.
  const token = await saToken('https://www.googleapis.com/auth/datastore');
  const docs = await listarFinanzas(token);
  console.log(`Documentos en "finanzas": ${docs.length}`);

  const cambios = [];
  const sinReconocer = new Set();

  for (const doc of docs) {
    const categoriaActual = doc.fields?.categoria?.stringValue ?? '';
    const nueva = normalizar(categoriaActual);
    if (nueva === null) continue; // ya estaba bien
    if (nueva === undefined) { sinReconocer.add(categoriaActual); continue; }
    cambios.push({ id: doc.name.split('/').pop(), name: doc.name, de: categoriaActual, a: nueva });
  }

  console.log('');
  console.log(`Cambios detectados: ${cambios.length}`);
  cambios.forEach(c => console.log(`  ${c.id}:  "${c.de}"  →  "${c.a}"`));

  if (sinReconocer.size){
    console.log('');
    console.log('⚠️  Categorías sin mapeo conocido (NO se tocan, revisar a mano si hace falta):');
    [...sinReconocer].forEach(c => console.log(`  "${c}"`));
  }

  if (!EXECUTE){
    console.log('');
    console.log('Dry-run terminado. Nada se escribió. Para aplicar de verdad: node migrar-categorias.js --execute');
    return;
  }

  console.log('');
  console.log('Aplicando cambios...');
  for (const c of cambios){
    await actualizarCategoria(token, c.name, c.a);
    console.log(`  ✓ ${c.id} actualizado a "${c.a}"`);
  }
  console.log(`Listo. ${cambios.length} documento(s) actualizado(s).`);
}

main().catch(e => { console.error('Error:', e.message || e); process.exit(1); });
