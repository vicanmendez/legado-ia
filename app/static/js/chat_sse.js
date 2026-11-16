/* Recepción de fragmentos en streaming SSE para conversaciones con la simulación */
(function () {
  "use strict";
  function connectStream(streamUrl, targetElement) {
    const source = new EventSource(streamUrl, { withCredentials: true });
    source.addEventListener("token", function (evt) {
      if (targetElement) {
        targetElement.textContent += (targetElement.textContent ? " " : "") + evt.data;
      }
    });
    source.addEventListener("done", function () {
      source.close();
    });
    return source;
  }

  window.LegadoChatSSE = { connectStream: connectStream };
})();
