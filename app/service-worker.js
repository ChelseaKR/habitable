// SPDX-License-Identifier: AGPL-3.0-or-later
// habitable — offline shell cache. API responses are never cached.
"use strict";

var CACHE = "habitable-shell-v1";

// Relative URLs so the worker matches however the shell is served.
var SHELL = [
  "./",
  "index.html",
  "styles.css",
  "app.js",
  "i18n/en.json",
  "i18n/es.json",
  "manifest.webmanifest",
  "icons/icon.svg"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(SHELL);
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.map(function (key) {
          if (key !== CACHE) {
            return caches.delete(key);
          }
          return null;
        })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

self.addEventListener("fetch", function (event) {
  var request = event.request;

  // Only handle GET; let writes (POST etc.) go straight to the network.
  if (request.method !== "GET") {
    return;
  }

  var url = new URL(request.url);

  // Network-only for the API: never cache evidence or status responses.
  if (url.pathname.indexOf("/api/") === 0) {
    event.respondWith(fetch(request));
    return;
  }

  // Cache-first for the static shell, with a network fallback that
  // refreshes the cache opportunistically.
  event.respondWith(
    caches.match(request).then(function (cached) {
      if (cached) {
        return cached;
      }
      return fetch(request).then(function (response) {
        if (response && response.ok && url.origin === self.location.origin) {
          var copy = response.clone();
          caches.open(CACHE).then(function (cache) {
            cache.put(request, copy);
          });
        }
        return response;
      });
    }).catch(function () {
      // Last resort for navigations when fully offline.
      if (request.mode === "navigate") {
        return caches.match("index.html");
      }
      return Response.error();
    })
  );
});
