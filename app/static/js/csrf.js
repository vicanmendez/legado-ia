/* Inyección automática de cabecera X-CSRF-Token en todas las peticiones HTMX y fetch locales */
(function () {
  "use strict";
  document.addEventListener("htmx:configRequest", function (evt) {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && evt.detail && evt.detail.headers) {
      evt.detail.headers["X-CSRF-Token"] = meta.getAttribute("content") || "";
    }
  });
})();
