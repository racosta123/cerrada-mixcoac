/* Copia este archivo como config.js y rellena con tus valores reales.
   config.js NO debe contener secretos del Worker ni de la Shelly. */
const CONFIG = {
  firebase: {
    apiKey: "AIzaSyDC85fCK9k_ZpyrKt9a_jBjTfGjMNWxtLA",       // RESTRINGIR a racosta123.github.io en Google Cloud Console
    authDomain: "cerrada-mixcoac.firebaseapp.com",
    projectId: "cerrada-mixcoac",
    storageBucket: "cerrada-mixcoac.firebasestorage.app",
    messagingSenderId: "262455932994",
    appId: "1:262455932994:web:79f8d3700e9b46440ed5db",
  },
  workerUrl: "https://mixcoac-proxy.acosta4770.workers.dev",
  appCheckSiteKey: "",  // App Check — pendiente: pega aquí tu reCAPTCHA v3 site key real
  vapidKey: "",         // FCM Web Push — pendiente: pega aquí tu clave pública VAPID real
};
