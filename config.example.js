/* Copia este archivo como config.js y rellena con tus valores reales.
   config.js NO debe contener secretos del Worker ni de la Shelly. */
const CONFIG = {
  firebase: {
    apiKey: "TU_API_KEY",                       // RESTRINGIR a racosta123.github.io en Google Cloud Console
    authDomain: "cerrada-mixcoac.firebaseapp.com",
    projectId: "cerrada-mixcoac",
    storageBucket: "cerrada-mixcoac.appspot.com",
    messagingSenderId: "TU_SENDER_ID",
    appId: "TU_APP_ID",
  },
  workerUrl: "https://mixcoac-proxy.acosta4770.workers.dev",
  appCheckSiteKey: "TU_RECAPTCHA_V3_SITE_KEY",  // App Check
  vapidKey: "TU_VAPID_KEY_WEB_PUSH",            // FCM Web Push (clave PÚBLICA correcta)
};
