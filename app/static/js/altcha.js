/* Resolución local automática de desafío proof-of-work ALTCHA sin scripts externos (CSP 'self') */
(function () {
  "use strict";
  async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function solveAltcha(challengeObj) {
    const max = challengeObj.maxnumber || 10000;
    for (let n = 0; n <= max; n++) {
      const candidate = await sha256Hex(challengeObj.salt + String(n));
      if (candidate === challengeObj.challenge) {
        const payload = {
          algorithm: challengeObj.algorithm,
          challenge: challengeObj.challenge,
          number: n,
          salt: challengeObj.salt,
          signature: challengeObj.signature,
        };
        return btoa(JSON.stringify(payload));
      }
    }
    throw new Error("No se pudo resolver el desafío ALTCHA");
  }

  async function initAltchaWidget() {
    const input = document.getElementById("altcha_payload");
    const statusBox = document.getElementById("altcha_status");
    const submitBtn = document.getElementById("altcha_submit_btn");
    if (!input) return;

    try {
      if (statusBox) statusBox.textContent = "Verificando desafío de seguridad ALTCHA local...";
      const resp = await fetch("/auth/altcha-challenge", { credentials: "same-origin" });
      const ch = await resp.json();
      const solved = await solveAltcha(ch);
      input.value = solved;
      if (statusBox) {
        statusBox.textContent = "✓ Protección antiautomatización ALTCHA verificada";
        statusBox.classList.add("verified");
      }
      if (submitBtn) submitBtn.disabled = false;
    } catch (err) {
      if (statusBox) statusBox.textContent = "Error al resolver ALTCHA: recarga la página";
    }
  }

  window.LegadoAltcha = { solveAltcha: solveAltcha, initAltchaWidget: initAltchaWidget };
  document.addEventListener("DOMContentLoaded", initAltchaWidget);
})();
