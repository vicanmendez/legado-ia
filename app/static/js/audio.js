/* Grabación de voz en navegador con MediaRecorder y subida a /trainer/audio/upload */
(function () {
  "use strict";
  let mediaRecorder = null;
  let chunks = [];

  async function startRecording() {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    chunks = [];
    mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm" });
    mediaRecorder.ondataavailable = function (e) {
      if (e.data && e.data.size > 0) chunks.push(e.data);
    };
    mediaRecorder.start();
  }

  function stopRecording() {
    return new Promise(function (resolve) {
      if (!mediaRecorder) return resolve(null);
      mediaRecorder.onstop = function () {
        const blob = new Blob(chunks, { type: "audio/webm" });
        resolve(blob);
      };
      mediaRecorder.stop();
    });
  }

  window.LegadoAudio = { startRecording: startRecording, stopRecording: stopRecording };
})();
