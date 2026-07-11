/* Mapa de categorías compartido por migrar-categorias.js y respaldo-diagnostico.js.
   Vive en un solo lugar para que el dry-run que se muestra antes de migrar
   sea EXACTAMENTE el mismo cálculo que usará la migración real. */

// Categoría final permitida (debe coincidir exacto con el <select> de index.html).
const CATEGORIAS_VALIDAS = ['Cuota', 'Multa', 'Mantenimiento', 'Seguridad', 'Limpieza', 'Mejoras', 'Servicios', 'Otro'];

// Alias conocidos → categoría normalizada. Todo en minúsculas para comparar sin distinguir mayúsculas.
// Lo que no aparezca aquí y no sea ya una de las CATEGORIAS_VALIDAS se reporta aparte, sin tocarlo
// (no se fuerza a "Otro" a ciegas — mejor que alguien lo revise a mano).
const ALIAS = {
  'cuota': 'Cuota', 'cuotas': 'Cuota',
  'multa': 'Multa', 'multas': 'Multa',
  'mantenimiento': 'Mantenimiento',
  'seguridad': 'Seguridad',
  'limpieza': 'Limpieza',
  'mejoras': 'Mejoras', 'mejora': 'Mejoras',
  'servicios': 'Servicios', 'servicio': 'Servicios',
  'otro': 'Otro', 'otros': 'Otro',
};

function normalizar(categoriaOriginal){
  const cat = (categoriaOriginal || '').trim();
  if (CATEGORIAS_VALIDAS.includes(cat)) return null; // ya está bien, no hay que tocarlo
  const alias = ALIAS[cat.toLowerCase()];
  if (alias) return alias;
  return undefined; // no se reconoce — se reporta para revisión manual, no se toca
}

module.exports = { CATEGORIAS_VALIDAS, ALIAS, normalizar };
