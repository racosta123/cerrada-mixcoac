# Cerrada Mixcoac — PWA de control de acceso

Proyecto **aislado** (Firebase, repo y Worker propios). Diseño tipo Punta Kino
(oscuro/dorado, esquinas redondeadas). Funcionalidad tipo CerradaApp.

## Roles
- **Master** (tú) y **Admin**: abren las 4 puertas + bitácora general. Master crea admins y residentes; admin solo residentes.
- **Residente**: abre las 4 puertas, genera invitaciones QR (solo puerta de visitantes), recibe push de sus esclavos/visitantes, ve su historial.
- **Esclavo** (hasta 4 por residente): abre las 4 puertas, también puede invitar.

## Seguridad (regla de oro aplicada)
- El cliente **nunca** toca la Shelly ni guarda llaves. Todo pasa por el Worker.
- El Worker **verifica el ID token de Firebase** y el **rol** antes de abrir.
- Las **aperturas e invitaciones solo las escribe el Worker** (service account). Las reglas de Firestore bloquean escritura desde el cliente.
- El **alta de usuarios** la hace el Worker con Admin SDK → registro público cerrado.
- QR firmado con HMAC (`QR_SECRET`), con expiración y usos. Pre-sincronizado al lector para abrir **sin internet** en la cerrada.
- App Check (reCAPTCHA v3) activable.

## Archivos
- `index.html` `app.js` `config.example.js` — la PWA (GitHub Pages)
- `worker.js` `wrangler.toml` — Cloudflare Worker (Shelly + Firebase admin)
- `firestore.rules` — reglas blindadas
- `manifest.json` `sw.js` `firebase-messaging-sw.js` `icons/` — PWA

## Despliegue (resumen)
1. **Firebase**: crea proyecto `cerrada-mixcoac`. Activa Auth (correo/contraseña), Firestore, Cloud Messaging.
2. Copia `config.example.js` → `config.js` y rellena. **Restringe la API key** a `racosta123.github.io` en Google Cloud Console.
3. Pega tus reglas (`firestore.rules`) y publícalas.
4. **Worker**: `wrangler deploy`. Carga secrets:
   `SHELLY_HOST SHELLY_AUTH_KEY FIREBASE_PROJECT SA_EMAIL SA_PRIVATE_KEY QR_SECRET READER_KEY READER_SYNC_URL`
5. Crea tu usuario master a mano: en Auth crea la cuenta, y en Firestore `usuarios/{tu-uid}` pon `{ nombre, rol:"master" }`.
6. **GitHub Pages**: sube todo al repo `racosta123/cerrada-mixcoac`, activa Pages.

## Pendiente (después del desarrollo, como acordamos)
- Elegir el **lector QR físico** con API local para pre-sync offline (ZKTeco QR series u otro con endpoint local).
- Imagen real de la cerrada para el index (la mandas tú).
- Logo Diagonal Catorce si lo quieres en algún lado (mándame el archivo real).
