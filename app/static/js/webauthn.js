/* Envoltorio mínimo sobre navigator.credentials (WebAuthn Passkeys) sin librerías externas */
(function () {
  "use strict";
  async function registerPasskey(optionsUrl, verifyUrl, deviceName) {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
    const optResp = await fetch(optionsUrl, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      credentials: "same-origin",
    });
    const opts = await optResp.json();
    const cred = await navigator.credentials.create({ publicKey: opts });
    const verifyResp = await fetch(verifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      credentials: "same-origin",
      body: JSON.stringify({
        credential_id_b64: cred.id,
        challenge_b64: opts.challenge,
        device_name: deviceName,
      }),
    });
    return verifyResp.json();
  }

  window.LegadoWebAuthn = { registerPasskey: registerPasskey };
})();
