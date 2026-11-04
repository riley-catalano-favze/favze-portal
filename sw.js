// Favze Portal Service Worker - Push Notifications
self.addEventListener('install', function(e) {
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(clients.claim());
});

self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data ? e.data.json() : {}; } catch(err) { data = { title: 'Favze', body: e.data ? e.data.text() : '' }; }

  var title = data.title || 'Favze';
  var options = {
    body: data.body || '',
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    data: { url: data.url || 'https://portal.favze.com' },
    requireInteraction: false,
  };

  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  var url = (e.notification.data && e.notification.data.url) || 'https://portal.favze.com';
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].url === url && 'focus' in list[i]) return list[i].focus();
    }
    if (clients.openWindow) return clients.openWindow(url);
  }));
});
