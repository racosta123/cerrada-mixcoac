importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');
// Estos valores son públicos (mismos del config.js). Rellénalos.
firebase.initializeApp({
  apiKey: "TU_API_KEY",
  authDomain: "cerrada-mixcoac.firebaseapp.com",
  projectId: "cerrada-mixcoac",
  messagingSenderId: "TU_SENDER_ID",
  appId: "TU_APP_ID",
});
const messaging = firebase.messaging();
messaging.onBackgroundMessage(p => {
  self.registration.showNotification(p.notification?.title || 'Cerrada Mixcoac', {
    body: p.notification?.body || '', icon: 'icons/icon-192.png',
  });
});
