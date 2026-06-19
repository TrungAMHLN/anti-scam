// Runs in the page's MAIN world. It cannot use chrome.* APIs.
// It reports sensitive website permission/API requests back to the content script.
(function () {
  if (window.__antiscamPageHooksInstalled) return;
  window.__antiscamPageHooksInstalled = true;

  var sendPerm = function (name) {
    try {
      window.dispatchEvent(new CustomEvent('__antiscam_perm', { detail: { name: String(name || 'unknown') } }));
    } catch (_) {}
  };

  var safeWrap = function (obj, key, name, wrapperFactory) {
    try {
      if (!obj || !obj[key] || obj[key].__antiscamWrapped) return false;
      var original = obj[key];
      var wrapped = wrapperFactory(original);
      try { wrapped.__antiscamWrapped = true; } catch (_) {}
      obj[key] = wrapped;
      return true;
    } catch (_) { return false; }
  };

  var install = function () {
    // Generic Permissions API: navigator.permissions.query({ name })
    try {
      if (navigator.permissions && navigator.permissions.query && !navigator.permissions.query.__antiscamWrapped) {
        var originalQuery = navigator.permissions.query.bind(navigator.permissions);
        var queryWrapped = function (descriptor) {
          try {
            if (descriptor && descriptor.name) sendPerm('permissions-' + descriptor.name);
          } catch (_) {}
          return originalQuery.apply(navigator.permissions, arguments);
        };
        queryWrapped.__antiscamWrapped = true;
        navigator.permissions.query = queryWrapped;
      }
    } catch (_) {}

    // Notification permission prompt.
    try {
      if (window.Notification && Notification.requestPermission && !Notification.requestPermission.__antiscamWrapped) {
        var originalNotification = Notification.requestPermission.bind(Notification);
        var notificationWrapped = function () {
          sendPerm('notification');
          return originalNotification.apply(Notification, arguments);
        };
        notificationWrapped.__antiscamWrapped = true;
        Notification.requestPermission = notificationWrapped;
      }
    } catch (_) {}

    // Geolocation.
    try {
      if (navigator.geolocation) {
        safeWrap(navigator.geolocation, 'getCurrentPosition', 'geolocation', function (orig) {
          return function () { sendPerm('geolocation'); return orig.apply(navigator.geolocation, arguments); };
        });
        safeWrap(navigator.geolocation, 'watchPosition', 'geolocation', function (orig) {
          return function () { sendPerm('geolocation'); return orig.apply(navigator.geolocation, arguments); };
        });
      }
    } catch (_) {}

    // Camera / microphone.
    try {
      if (navigator.mediaDevices) {
        safeWrap(navigator.mediaDevices, 'getUserMedia', 'camera-microphone', function (orig) {
          return function (constraints) {
            try {
              var c = constraints || {};
              sendPerm(c.video && c.audio ? 'camera-microphone' : (c.video ? 'camera' : (c.audio ? 'microphone' : 'media')));
            } catch (_) { sendPerm('camera-microphone'); }
            return orig.apply(navigator.mediaDevices, arguments);
          };
        });
      }
    } catch (_) {}

    // Clipboard read/write.
    try {
      if (navigator.clipboard) {
        ['read', 'readText', 'write', 'writeText'].forEach(function (k) {
          safeWrap(navigator.clipboard, k, 'clipboard', function (orig) {
            return function () { sendPerm('clipboard-' + k); return orig.apply(navigator.clipboard, arguments); };
          });
        });
      }
    } catch (_) {}

    // Fullscreen.
    try {
      if (window.Element && Element.prototype) {
        safeWrap(Element.prototype, 'requestFullscreen', 'fullscreen', function (orig) {
          return function () { sendPerm('fullscreen'); return orig.apply(this, arguments); };
        });
      }
    } catch (_) {}

    // Payment Request.
    try {
      if (window.PaymentRequest && !window.PaymentRequest.__antiscamWrapped) {
        var OriginalPaymentRequest = window.PaymentRequest;
        var PaymentRequestWrapped = function () {
          sendPerm('payment-request');
          return Reflect.construct(OriginalPaymentRequest, arguments, new.target || OriginalPaymentRequest);
        };
        PaymentRequestWrapped.prototype = OriginalPaymentRequest.prototype;
        try { Object.setPrototypeOf(PaymentRequestWrapped, OriginalPaymentRequest); } catch (_) {}
        PaymentRequestWrapped.__antiscamWrapped = true;
        window.PaymentRequest = PaymentRequestWrapped;
      }
    } catch (_) {}

    // MIDI.
    try {
      safeWrap(navigator, 'requestMIDIAccess', 'midi', function (orig) {
        return function () { sendPerm('midi'); return orig.apply(navigator, arguments); };
      });
    } catch (_) {}

    // Motion/orientation permissions on mobile Safari-like APIs.
    try {
      ['DeviceMotionEvent', 'DeviceOrientationEvent'].forEach(function (name) {
        var Ctor = window[name];
        if (Ctor && Ctor.requestPermission && !Ctor.requestPermission.__antiscamWrapped) {
          var original = Ctor.requestPermission.bind(Ctor);
          var wrapped = function () { sendPerm('sensors'); return original.apply(Ctor, arguments); };
          wrapped.__antiscamWrapped = true;
          Ctor.requestPermission = wrapped;
        }
      });
    } catch (_) {}

    // Sensor constructors.
    try {
      ['Accelerometer', 'Gyroscope', 'Magnetometer', 'AmbientLightSensor'].forEach(function (name) {
        var Ctor = window[name];
        if (!Ctor || Ctor.__antiscamWrapped) return;
        var Wrapped = function () {
          sendPerm('sensors');
          return Reflect.construct(Ctor, arguments, new.target || Ctor);
        };
        Wrapped.prototype = Ctor.prototype;
        try { Object.setPrototypeOf(Wrapped, Ctor); } catch (_) {}
        Wrapped.__antiscamWrapped = true;
        window[name] = Wrapped;
      });
    } catch (_) {}
  };

  install();
  // Some APIs may appear later; retry shortly without keeping a long-running timer.
  var tries = 0;
  var timer = setInterval(function () {
    tries += 1;
    install();
    if (tries >= 20) clearInterval(timer);
  }, 500);
})();
