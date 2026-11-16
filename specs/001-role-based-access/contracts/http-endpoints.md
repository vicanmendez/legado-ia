# Interface Contracts: Endpoints HTTP / HTMX (`legado-ia`)

**Feature**: `001-role-based-access` (Contratos HTTP Partes 1–6)
**Date**: 2026-11-16

---

## Reglas Transversales de Interfaz

1. **Cookies de Sesión**: Cookie `legado_session` con flags `HttpOnly; Secure; SameSite=Strict; Path=/`.
2. **Protección CSRF**: Todo endpoint `POST`, `PUT`, `PATCH`, `DELETE` exige el token CSRF de la sesión actual ya sea en el campo de formulario `_csrf_token` o en la cabecera `X-CSRF-Token` (inyectada automáticamente en HTMX por `/static/js/csrf.js`).
3. **Cabeceras de Respuesta Obligatorias**:
   - `Content-Security-Policy: default-src 'self'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: no-referrer`
   - `Permissions-Policy: microphone=(self), camera=(), geolocation=()`

---

## 1. Autenticación, Captcha ALTCHA, Invitaciones y Recuperación (`/auth`)

| Método | Ruta | Acceso | Descripción y Contrato |
|--------|------|--------|------------------------|
| `GET` | `/auth/altcha-challenge` | Público (rate-limited) | Devuelve JSON `{algorithm: "SHA-256", challenge, maxnumber, salt, signature}` firmado con `ALTCHA_HMAC_KEY`. |
| `GET` | `/auth/login` | Público | Renderiza `auth/login.html` con widget ALTCHA local y token CSRF pre-sesión. |
| `POST` | `/auth/login` | Público (slowapi IP+user) | Valida `_csrf_token`, payload ALTCHA (y que no esté en `altcha_consumed_challenges`) y credenciales Argon2id (o hash ficticio si el usuario no existe). Si es válido, crea sesión con `is_2fa_verified=False` (10 min), genera OTP de 6 dígitos en `otp_codes`, encola envío SMTP y redirige a `/auth/2fa`. |
| `GET` | `/auth/2fa` | Sesión `is_2fa_verified=False` | Renderiza `auth/verify_2fa.html` permitiendo introducir el código de 6 dígitos, usar una Passkey WebAuthn o elegir código de recuperación. |
| `POST` | `/auth/2fa/otp` | Sesión `is_2fa_verified=False` | Verifica el código de 6 dígitos (caducidad $\le 10$ min, intentos $\le 5$). Si acierta, invalida el OTP, regenera el ID de sesión de 256 bits, marca `is_2fa_verified=True` y redirige al panel del rol correspondiente. |
| `POST` | `/auth/2fa/recovery` | Sesión `is_2fa_verified=False` | Verifica un código de recuperación de un solo uso no consumido, lo marca con `used_at=now()`, regenera el ID de sesión, marca `is_2fa_verified=True` e informa cuántos códigos restan. |
| `POST` | `/auth/logout` | `require_user` | Revoca la sesión en BD (`revoked_at=now()`), limpia la cookie y redirige a `/auth/login`. |
| `GET` | `/auth/invite/{token}` | Público | Verifica que `sha256(token)` exista en `invitations`, no esté usado, revocado ni caducado. Renderiza `auth/register_invite.html`. |
| `POST` | `/auth/invite/{token}` | Público (slowapi) | Valida ALTCHA, crea usuario con rol `amigo` (o `albacea` según la invitación), genera su DEK cifrada con la KEK, marca la invitación como consumida y genera su lote inicial de códigos de recuperación mostrándolos por única vez en `auth/recovery_codes.html`. |

---

## 2. Segundo Factor y Gestión de Passkeys WebAuthn (`/webauthn`)

| Método | Ruta | Acceso | Descripción y Contrato |
|--------|------|--------|------------------------|
| `POST` | `/webauthn/register/options` | `require_user` | Genera opciones de registro con `py_webauthn` (`RP_ID`, `RP_NAME`, `userVerification="required"`), guarda el `challenge` efímero en `sessions.webauthn_challenge` y devuelve JSON. |
| `POST` | `/webauthn/register/verify` | `require_user` | Consume y borra `sessions.webauthn_challenge`, verifica la respuesta del navegador con `py_webauthn` y guarda la credencial en `webauthn_credentials`. |
| `POST` | `/webauthn/authenticate/options` | Sesión `is_2fa_verified=False` | Genera opciones de autenticación para las credenciales activas del usuario, guarda `challenge` de un solo uso en sesión y devuelve JSON. |
| `POST` | `/webauthn/authenticate/verify` | Sesión `is_2fa_verified=False` | Consume `challenge`, verifica firma y comprueba `new_sign_count > stored_sign_count`. Si detecta retroceso de contador, bloquea la credencial y registra alerta en `audit_log`. Si es válido, actualiza `sign_count`, regenera sesión con `is_2fa_verified=True` y redirige al panel. |
| `PATCH` | `/webauthn/credentials/{id}` | `require_user` | Renombra una credencial perteneciente al usuario actual. |
| `DELETE` | `/webauthn/credentials/{id}` | `require_user` | Revoca una credencial. Si es la última credencial activa, exige confirmación adicional con un código de recuperación válido. |

---

## 3. Panel del Entrenador: Conocimiento, Audio, Entrevista, Invitaciones y LLM (`/trainer`)

*Todos los endpoints bajo `/trainer` exigen `require_role("entrenador")`. Si `system_state.mode == "postumo"`, todas las operaciones de escritura sobre entradas, audio, personalidad y temas de entrevista devuelven `403 Forbidden (Modo Póstumo: solo lectura)`.*

| Método | Ruta | Descripción y Contrato |
|--------|------|------------------------|
| `GET` | `/trainer/entries` | Lista y filtra en memoria las entradas del entrenador (descifradas con su DEK). Soporta búsqueda HTMX (`?q=...&topic=...`). |
| `POST` | `/trainer/entries` | Crea una nueva entrada cifrando el texto con la DEK del entrenador. |
| `PUT` | `/trainer/entries/{id}` | Actualiza una entrada o confirma una transcripción (`status="confirmed"`). |
| `DELETE` | `/trainer/entries/{id}` | Borrado seguro: elimina la fila en `entries`, su registro en `audio_files` y sobrescribe/elimina el archivo cifrado en disco. |
| `POST` | `/trainer/audio/upload` | Recibe audio grabado (`MediaRecorder`), valida tamaño máximo y *magic bytes* MIME (`audio/webm`, `audio/ogg`, `audio/wav`), cifra en disco con la DEK del entrenador y encola transcripción en segundo plano con `faster-whisper`. |
| `GET` | `/trainer/personality` | Muestra el documento de personalidad activo y su historial de versiones. |
| `POST` | `/trainer/personality` | Guarda una nueva versión cifrada en `personality_doc` y la marca como activa. |
| `GET` | `/trainer/interview` | Muestra la lista de temas de entrevista guiada (`infancia`, `valores`, `trabajo`, `errores`, `consejos`) y su estado (`is_covered`). |
| `POST` | `/trainer/export` | Descarga en streaming (`StreamingResponse`) la base de conocimiento en formato `jsonl` o `txt`, registrando `KB_EXPORT` en `audit_log`. |
| `POST` | `/trainer/invitations` | Genera un enlace de invitación de un solo uso con token de 256 bits (mostrado una sola vez al entrenador; en BD solo se guarda `sha256(token)`). |
| `POST` | `/trainer/llm-settings` | Actualiza proveedor, `base_url`, `model_name` y cifra la `api_key` con AES-256-GCM (nunca se vuelve a mostrar en la interfaz). |

---

## 4. Panel del Amigo y Conversación en Streaming SSE (`/friend`)

*Exige `require_role("amigo")` (o el propietario de la conversación). Todas las consultas filtran estrictamente por `friend_id == current_user.id`.*

| Método | Ruta | Descripción y Contrato |
|--------|------|------------------------|
| `GET` | `/friend/conversations` | Lista las conversaciones del amigo actual descifrando sus títulos con la DEK del amigo. |
| `POST` | `/friend/conversations` | Inicia una nueva conversación cifrada con la DEK del amigo. |
| `GET` | `/friend/conversations/{id}` | Renderiza `friend/chat_room.html` con el aviso fijo de simulación (y aviso de fallecimiento si `mode == "postumo"`) y el historial de mensajes descifrado solo para el amigo propietario. |
| `POST` | `/friend/conversations/{id}/messages` | Valida cuota diaria de tokens y rate-limit, guarda el mensaje del amigo cifrado con su DEK y devuelve el contenedor HTMX que abre la conexión SSE de respuesta. |
| `GET` | `/friend/conversations/{id}/stream` | Endpoint `text/event-stream` (SSE): construye el prompt (personalidad + entradas recuperadas por `RetrievalStrategy` + historial reciente), ejecuta tool-calling de búsqueda web si procede envolviendo resultados con `[Información externa]`, transmite los fragmentos de texto saneados, inyecta por código el aviso de simulación e indicador de fuente externa, y persiste el mensaje final cifrado con la DEK del amigo. |

---

## 5. Albacea y Modo Póstumo (`/executor`)

*Exige `require_role("albacea")` o `require_role("entrenador")` según la acción.*

| Método | Ruta | Acceso | Descripción y Contrato |
|--------|------|--------|------------------------|
| `GET` | `/executor/panel` | `albacea` / `entrenador` | Muestra el estado actual (`activo`, `transicion_pendiente`, `postumo`), el plazo de espera y el historial de `succession_events`. |
| `POST` | `/executor/request-transition` | `albacea` | Inicia la solicitud de modo póstumo: cambia estado a `transicion_pendiente`, calcula `transition_confirmable_after`, registra en `audit_log` y envía notificaciones por email al entrenador y contactos de emergencia. |
| `POST` | `/executor/cancel-transition` | `entrenador` / `albacea` | Aborta inmediatamente una transición pendiente y restaura el estado `activo`, registrando el evento en `audit_log`. |
| `POST` | `/executor/confirm-posthumous` | `albacea` | Disponible únicamente cuando `now() >= transition_confirmable_after` y el estado sigue en `transicion_pendiente`. Activa el estado `postumo` (base de conocimiento en solo lectura, aviso póstumo en chats y gestión de invitaciones habilitada para el albacea). |
