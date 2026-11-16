---

description: "Task list for legado-ia implementation across 6 incremental parts"
---

# Tasks: Plataforma legado-ia (Acceso, Conocimiento, Conversación y Continuidad Póstuma)

**Input**: Design documents from `/specs/001-role-based-access/` (`plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/http-endpoints.md`, `contracts/cli-commands.md`, `quickstart.md`)

**Prerequisites**: `plan.md` (required), `spec.md` (required for user stories), `research.md`, `data-model.md`, `contracts/`

**Tests**: OBLIGATORIOS por Constitución (Principio X) y especificación del usuario (cobertura mínima del 80 % en módulos de seguridad, ejecutados tanto en SQLite como en MySQL/MariaDB).

**Organization**: Tareas organizadas por fase e historia de usuario (`US1` a `US6`), reflejando exactamente las 6 partes incrementales y desplegables del proyecto.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Ejecutable en paralelo (archivos distintos, sin dependencia de tareas incompletas de la misma fase)
- **[Story]**: Historia de usuario a la que pertenece (`[US1]` a `[US6]`)
- Incluye rutas exactas de archivos y restricciones literales de `data-model.md`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Inicialización del proyecto Python 3.12 con `uv`, estructura de paquetes, activos estáticos locales (`/static`) y herramientas de calidad (`ruff`, `mypy`, `bandit`, `pip-audit`).

- [X] T001 Crear la estructura de directorios del proyecto (`app/db`, `app/models`, `app/schemas`, `app/services`, `app/routers`, `app/templates`, `app/static`, `migrations/versions`, `tests/unit`, `tests/integration`, `tests/portability`) según `plan.md` en `app/__init__.py`
- [X] T002 Inicializar la configuración de `uv` con Python 3.12 y dependencias fijadas (`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `sqlalchemy`, `alembic`, `pymysql`, `jinja2`, `python-multipart`, `cryptography`, `argon2-cffi`, `aiosmtplib`, `py_webauthn`, `slowapi`, `httpx`, `faster-whisper`, `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `bandit`, `pip-audit`) en `pyproject.toml` y `uv.lock`
- [X] T003 [P] Crear la plantilla versionada de variables de entorno con las 25 variables requeridas (`APP_ENV`, `APP_BASE_URL`, `APP_SECRET_KEY`, `DB_ENGINE`, `DB_SQLITE_PATH`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSL_CA`, `ENCRYPTION_KEK_FILE`, `ENCRYPTION_KEK`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_STARTTLS`, `MAIL_FROM`, `ALTCHA_HMAC_KEY`, `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `WHISPER_MODEL`) en `.env.example`
- [X] T004 [P] Incorporar activos estáticos versionados sin CDN (`htmx.min.js` y hoja de estilos base) en `app/static/vendor/htmx.min.js` y `app/static/css/main.css`
- [X] T005 [P] Configurar reglas de linting, tipado estricto y análisis estático de seguridad (`ruff`, `mypy`, `bandit`, `pytest`) en `pyproject.toml` y `.pre-commit-config.yaml`
- [X] T006 [P] Crear configuración de contenedores con usuario `non-root` y soporte de Docker secrets (app + MariaDB `utf8mb4` + Ollama opcionales) en `Dockerfile` y `docker-compose.yml`

---

## Phase 2: Foundational (Blocking Prerequisites - Parte 1 Base Transversal)

**Purpose**: Configuración *fail-fast* (`pydantic-settings`), capa de base de datos dual SQLite/MariaDB (`SQLAlchemy 2.x` + `Alembic` con `render_as_batch=True`), cifrado por sobre AES-256-GCM + Argon2id, cabeceras de seguridad (`CSP: 'self'`), protección CSRF y auditoría transversal.

**⚠️ CRITICAL**: Ninguna historia de usuario puede comenzar hasta completar esta fase.

- [X] T007 Implementar `Settings` con `pydantic-settings` y validadores *fail-fast* en producción (abortar si falta algún secreto, si `APP_SECRET_KEY` < 32 bytes, si `APP_BASE_URL` no empieza por `https://` o si faltan campos del `DB_ENGINE` seleccionado) en `app/config.py`
- [X] T008 Implementar `DeclarativeBase` y tipos portables `EncryptedBlob` (`LargeBinary().with_variant(LONGBLOB(), "mysql", "mariadb")`) y `UTCDateTime` (`DateTime(timezone=True)` forzando `timezone.utc`) en `app/db/base.py`
- [X] T009 Implementar construcción de conexión con `sqlalchemy.engine.URL.create`, listeners `PRAGMA foreign_keys=ON` y `PRAGMA journal_mode=WAL` en SQLite, y soporte `utf8mb4` + TLS (`DB_SSL_CA` cuando el host no es local) en MySQL/MariaDB en `app/db/session.py`
- [X] T010 Configurar el entorno de migraciones Alembic con `render_as_batch=True` y carga de metadatos desde `app.db.base` en `alembic.ini` y `migrations/env.py`
- [X] T011 [P] Implementar el servicio criptográfico (cifrado por sobre AES-256-GCM con KEK externa y DEK por usuario con AAD `"{tabla}:{owner_id}"`, hash de contraseñas Argon2id con `argon2-cffi`, `DUMMY_PASSWORD_HASH` para anti-enumeración y generación de tokens de 256 bits con `secrets`) en `app/services/crypto.py`
- [X] T012 [P] Crear el modelo `AuditLog` (`audit_log`: `id Integer PK autoincrement`, `event_code String(64) NOT NULL index`, `actor_user_id Integer FK(users.id, ON DELETE SET NULL) NULLABLE index`, `ip_address String(45) NULLABLE`, `metadata_json Text NULLABLE`, `created_at UTCDateTime NOT NULL index`) en `app/models/audit.py`
- [X] T013 [P] Implementar el servicio de auditoría que sanea metadatos y garantiza que jamás se registren contraseñas, códigos, tokens, claves ni texto de recuerdos o conversaciones en `app/services/audit.py`
- [X] T014 [P] Implementar el cliente de envío de correo asíncrono en texto plano con `aiosmtplib` en `app/services/email.py`
- [X] T015 Implementar la factoría de la aplicación FastAPI con middlewares de cabeceras de seguridad (`Content-Security-Policy` con `'self'` sin `'unsafe-inline'`, `Strict-Transport-Security`, `X-Content-Type-Options=nosniff`, `X-Frame-Options=DENY`, `Referrer-Policy=no-referrer`, `Permissions-Policy: microphone=(self)`), validación CSRF por sesión y limitador `slowapi` en `app/main.py`
- [X] T016 [P] Crear plantilla base Jinja2 con escapado automático activado y script de inyección de cabecera `X-CSRF-Token` para peticiones HTMX en `app/templates/base.html` y `app/static/js/csrf.js`
- [X] T017 Configurar fixtures de pruebas parametrizadas para ejecutar la suite contra SQLite y contra MariaDB en `tests/conftest.py`
- [X] T018 [P] Escribir pruebas unitarias de validación *fail-fast* de `.env` y de cifrado por sobre AES-256-GCM / Argon2id en `tests/unit/test_config.py` y `tests/unit/test_crypto.py`

**Checkpoint**: Infraestructura transversal lista y verificada en SQLite y MariaDB.

---

## Phase 3: User Story 1 - Autenticación en Dos Pasos con Captcha ALTCHA, OTP por Email y Bloqueo Progresivo (Priority: P1) 🎯 MVP

**Goal**: Flujo de inicio de sesión en dos pasos ((1) usuario + contraseña Argon2id + captcha ALTCHA con HMAC y antirrepetición; (2) código OTP de 6 dígitos por email con caducidad de 10 min y máximo 5 intentos guardado como hash), estado de sesión "pendiente de 2FA" de corta duración, bloqueo progresivo exponencial por usuario e IP y mitigación contra enumeración de usuarios.

**Independent Test**: Iniciar sesión con un usuario activo verificando que el paso 1 solo emite una sesión `is_2fa_verified=False` incapaz de acceder a rutas protegidas, comprobar que el OTP caduca a los 10 min o al 5.º fallo, verificar el rechazo de soluciones ALTCHA repetidas y confirmar tiempos/mensajes idénticos ante usuarios inexistentes.

### Tests for User Story 1 ⚠️

> **NOTE: Escribir estas pruebas PRIMERO y verificar que FALLAN antes de la implementación**

- [X] T019 [P] [US1] Escribir pruebas unitarias de generación, validación HMAC, expiración y bloqueo de reutilización (replay) de desafíos ALTCHA en `tests/unit/test_altcha.py`
- [X] T020 [P] [US1] Escribir pruebas de integración para login en 2 pasos, intento de bypass de 2FA con sesión en paso 1, expiración y límite de 5 intentos de OTP, anti-enumeración de usuarios y bloqueo progresivo por fuerza bruta en `tests/integration/test_auth_2fa.py`

### Implementation for User Story 1

- [X] T021 [P] [US1] Crear modelos `User` (`users`: `id Integer PK autoincrement`, `username String(64) UNIQUE NOT NULL index`, `email String(255) UNIQUE NOT NULL index`, `password_hash String(255) NOT NULL`, `role String(20) NOT NULL index` con valores `"entrenador"|"amigo"|"albacea"`, `status String(20) NOT NULL default="active"` con valores `"active"|"disabled"|"locked"`, `failed_attempts Integer NOT NULL default=0`, `locked_until UTCDateTime NULLABLE`, `created_at UTCDateTime NOT NULL`, `updated_at UTCDateTime NOT NULL`), `UserKey` (`user_keys`: `id Integer PK autoincrement`, `user_id Integer FK(users.id, ON DELETE CASCADE) UNIQUE NOT NULL`, `encrypted_dek EncryptedBlob NOT NULL`, `key_version Integer NOT NULL default=1`, `rotated_at UTCDateTime NOT NULL`), `Session` (`sessions`: `id Integer PK autoincrement`, `session_token_hash String(64) UNIQUE NOT NULL index`, `user_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `is_2fa_verified Boolean NOT NULL default=False`, `csrf_token String(64) NOT NULL`, `webauthn_challenge LargeBinary(128) NULLABLE`, `ip_address String(45) NULLABLE`, `user_agent String(255) NULLABLE`, `created_at UTCDateTime NOT NULL`, `last_activity_at UTCDateTime NOT NULL`, `expires_at UTCDateTime NOT NULL index`, `revoked_at UTCDateTime NULLABLE`), `OTPCode` (`otp_codes`: `id Integer PK autoincrement`, `user_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `code_hash String(255) NOT NULL`, `attempts Integer NOT NULL default=0`, `expires_at UTCDateTime NOT NULL index`, `consumed_at UTCDateTime NULLABLE`, `created_at UTCDateTime NOT NULL`) y `AltchaConsumedChallenge` (`altcha_consumed_challenges`: `id Integer PK autoincrement`, `challenge_hash String(64) UNIQUE NOT NULL index`, `expires_at UTCDateTime NOT NULL index`) en `app/models/user.py`
- [X] T022 [P] [US1] Crear esquemas Pydantic de validación de entrada para login paso 1, desafío ALTCHA y verificación de código OTP de 6 dígitos en `app/schemas/auth.py`
- [X] T023 [US1] Implementar el servicio ALTCHA con firma HMAC (`ALTCHA_HMAC_KEY`) y registro de desafíos consumidos en `altcha_consumed_challenges` en `app/services/altcha.py`
- [X] T024 [US1] Implementar el servicio de autenticación en dos pasos (verificación Argon2id con `DUMMY_PASSWORD_HASH` cuando el usuario no existe, backoff exponencial en `failed_attempts`/`locked_until`, emisión de un único OTP activo de 6 dígitos con `secrets` guardado como hash con caducidad de 10 min y máximo 5 intentos, y creación/regeneración de sesiones de 256 bits) en `app/services/auth.py`
- [X] T025 [US1] Implementar endpoints `GET /auth/altcha-challenge`, `GET /auth/login`, `POST /auth/login`, `GET /auth/2fa` y `POST /auth/2fa/otp` con límites `slowapi` en `app/routers/auth.py`
- [X] T026 [P] [US1] Crear plantillas Jinja2 de login y segundo factor, plantilla de correo OTP en texto plano y script local de resolución ALTCHA en `app/templates/auth/login.html`, `app/templates/auth/verify_2fa.html`, `app/templates/emails/otp_code.txt` y `app/static/js/altcha.js`

**Checkpoint**: User Story 1 funcional y verificable de forma autónoma.

---

## Phase 4: User Story 2 - Aislamiento Estricto por Rol, Invitaciones de Un Solo Uso y Códigos de Recuperación (Priority: P1)

**Goal**: Registro cerrado exclusivo por invitación del entrenador (token aleatorio de 256 bits guardado como hash, con caducidad y uso único), generación de códigos de recuperación de un solo uso al activar la cuenta, cierre y caducidad de sesión por inactividad, y dependencias `require_user` / `require_role` que impiden a un amigo acceder a cualquier funcionalidad del entrenador.

**Independent Test**: Inicializar un entrenador con CLI, generar una invitación, registrar un amigo consumiendo el enlace una vez, comprobar rechazo al reutilizar la invitación, verificar que el amigo recibe `403 Forbidden` en todas las rutas del entrenador, iniciar sesión con un código de recuperación comprobando su invalidación tras el primer uso y verificar la caducidad por inactividad.

### Tests for User Story 2 ⚠️

- [X] T027 [P] [US2] Escribir pruebas de integración para uso único y caducidad de invitaciones, consumo único de códigos de recuperación, denegación de acceso de `amigo` a rutas de `entrenador`, validación CSRF y caducidad/cierre de sesión en `tests/integration/test_rbac_csrf.py`

### Implementation for User Story 2

- [X] T028 [P] [US2] Añadir modelos `Invitation` (`invitations`: `id Integer PK autoincrement`, `token_hash String(64) UNIQUE NOT NULL index`, `target_role String(20) NOT NULL default="amigo"`, `recipient_hint String(120) NULLABLE`, `created_by_id Integer FK(users.id) NOT NULL`, `used_by_id Integer FK(users.id) NULLABLE`, `expires_at UTCDateTime NOT NULL index`, `used_at UTCDateTime NULLABLE`, `revoked_at UTCDateTime NULLABLE`, `created_at UTCDateTime NOT NULL`) y `RecoveryCode` (`recovery_codes`: `id Integer PK autoincrement`, `user_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `code_hash String(255) NOT NULL`, `used_at UTCDateTime NULLABLE`, `created_at UTCDateTime NOT NULL`) en `app/models/user.py` y generar la primera migración Alembic (`render_as_batch=True`) en `migrations/versions/0001_initial_auth_and_audit.py`
- [X] T029 [US2] Implementar dependencias de seguridad FastAPI `require_user` (exigiendo `is_2fa_verified=True`, sesión no revocada y actualizando `last_activity_at` tras verificar caducidad por inactividad), `require_role("entrenador"|"amigo"|"albacea")` (denegando por defecto y auditando accesos denegados) y `verify_csrf` en `app/routers/dependencies.py`
- [X] T030 [US2] Ampliar `app/services/auth.py` y `app/schemas/auth.py` con creación y consumo atómico de invitaciones (token de 256 bits hasheado con SHA-256), generación y verificación de lotes de códigos de recuperación de un solo uso (guardados como hash) e invalidación de sesión al hacer logout
- [X] T031 [US2] Implementar endpoints `GET /auth/invite/{token}`, `POST /auth/invite/{token}`, `POST /auth/2fa/recovery`, `POST /auth/logout` en `app/routers/auth.py` y `POST /trainer/invitations`, `GET /trainer/invitations` en `app/routers/trainer.py`
- [X] T032 [P] [US2] Implementar el comando CLI `init-trainer` para aprovisionar la cuenta inicial del entrenador, su DEK cifrada y sus códigos de recuperación de un solo uso en `app/cli.py`
- [X] T033 [P] [US2] Crear plantillas Jinja2 de registro por invitación, visualización única de códigos de recuperación y gestión de invitaciones del entrenador en `app/templates/auth/register_invite.html`, `app/templates/auth/recovery_codes.html`, `app/templates/trainer/invitations.html` y `app/templates/emails/invitation.txt`

**Checkpoint**: Parte 2 (Sistema de acceso, roles, 2FA por email, invitaciones y códigos de recuperación) completa y desplegable por sí sola.

---

## Phase 5: User Story 3 - Segundo Factor y Gestión de Passkeys WebAuthn (Priority: P2)

**Goal**: Soporte de Passkeys WebAuthn (`py_webauthn`) como segundo factor en el paso 2 del login con `userVerification=required`, `challenge` de un solo uso en sesión, verificación del contador de firmas (`sign_count`) para detectar credenciales clonadas y gestión desde el perfil (listar, renombrar y revocar con protección de la última credencial).

**Independent Test**: Registrar una passkey con un autenticador virtual, completar el paso 2 del login con ella, comprobar el rechazo ante repetición del `challenge` o retroceso del contador de firmas, e intentar revocar la última passkey sin código de recuperación verificando que la operación es bloqueada.

### Tests for User Story 3 ⚠️

- [X] T034 [P] [US3] Escribir pruebas de integración con autenticador virtual WebAuthn cubriendo registro, login en paso 2, rechazo por replay de `challenge`, detección de credencial clonada por retroceso de `sign_count` y restricción al revocar la última credencial en `tests/integration/test_webauthn.py`

### Implementation for User Story 3

- [X] T035 [P] [US3] Crear el modelo `WebAuthnCredential` (`webauthn_credentials`: `id Integer PK autoincrement`, `user_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `credential_id LargeBinary(512) UNIQUE NOT NULL`, `public_key LargeBinary(1024) NOT NULL`, `sign_count Integer NOT NULL default=0`, `device_name String(100) NOT NULL`, `transports String(120) NULLABLE`, `created_at UTCDateTime NOT NULL`, `last_used_at UTCDateTime NULLABLE`, `revoked_at UTCDateTime NULLABLE`) en `app/models/webauthn.py` y migración Alembic en `migrations/versions/0002_webauthn_credentials.py`
- [X] T036 [P] [US3] Crear esquemas Pydantic para opciones y verificación de registro/autenticación WebAuthn, renombrado y revocación con código de recuperación en `app/schemas/webauthn.py`
- [X] T037 [US3] Implementar el servicio WebAuthn con `py_webauthn` tomando `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME` y origen `APP_BASE_URL`, exigiendo `userVerification="required"`, consumiendo el `webauthn_challenge` de un solo uso en `sessions` y validando el incremento de `sign_count` en `app/services/webauthn.py`
- [X] T038 [US3] Implementar endpoints `POST /webauthn/register/options`, `POST /webauthn/register/verify`, `POST /webauthn/authenticate/options`, `POST /webauthn/authenticate/verify`, `PATCH /webauthn/credentials/{id}` y `DELETE /webauthn/credentials/{id}` en `app/routers/webauthn.py`
- [X] T039 [P] [US3] Crear plantilla de seguridad del perfil y script JS nativo mínimo (`navigator.credentials.create` y `navigator.credentials.get`, sin librerías externas) en `app/templates/profile/security.html` y `app/static/js/webauthn.js`

**Checkpoint**: Parte 3 (Passkeys WebAuthn y gestión de factores en perfil) completa y desplegable.

---

## Phase 6: User Story 4 - Base de Conocimiento Cifrada, Grabación de Voz (`faster-whisper`) y Modo Entrevista (Priority: P2)

**Goal**: Panel exclusivo del entrenador para crear, editar, buscar en memoria y borrar de forma segura entradas de conocimiento, grabar/subir audio validado por contenido MIME real y cifrado en disco con la DEK del entrenador, transcribir voz en segundo plano con `faster-whisper` (editable antes de confirmar), versionar el documento de personalidad, usar el modo entrevista guiada y exportar la base en streaming a `JSONL` y `TXT`.

**Independent Test**: Como entrenador, crear entradas, versiones de personalidad y grabaciones de audio; verificar su transcripción editable; inspeccionar los bytes del archivo SQLite y de la carpeta de audio confirmando que ningún texto en claro aparece en reposo; exportar a `JSONL`/`TXT` verificando su registro en `audit_log`; y confirmar que un usuario `amigo` recibe `403 Forbidden` en todos estos endpoints.

### Tests for User Story 4 ⚠️

- [X] T040 [P] [US4] Escribir pruebas de integración para CRUD de entradas y personalidad, validación de *magic bytes* y límites de subida de audio, transcripción en segundo plano, exportación `JSONL`/`TXT` auditada, verificación binaria de ausencia de texto en claro en el fichero SQLite y bloqueo total al rol `amigo` en `tests/integration/test_knowledge.py`

### Implementation for User Story 4

- [X] T041 [P] [US4] Crear modelos `Entry` (`entries`: `id Integer PK autoincrement`, `trainer_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `topic String(120) NOT NULL index`, `entry_date UTCDateTime NOT NULL index`, `encrypted_content EncryptedBlob NOT NULL`, `status String(24) NOT NULL default="confirmed"` con valores `"draft_transcription"|"confirmed"`, `interview_topic_id Integer FK(interview_topics.id, ON DELETE SET NULL) NULLABLE`, `created_at UTCDateTime NOT NULL`, `updated_at UTCDateTime NOT NULL`), `AudioFile` (`audio_files`: `id Integer PK autoincrement`, `entry_id Integer FK(entries.id, ON DELETE CASCADE) UNIQUE NOT NULL`, `trainer_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `storage_rel_path String(255) UNIQUE NOT NULL`, `mime_type String(64) NOT NULL`, `sha256_hash String(64) NOT NULL`, `size_bytes Integer NOT NULL`, `transcription_status String(24) NOT NULL default="pending"` con valores `"pending"|"processing"|"completed"|"failed"`, `created_at UTCDateTime NOT NULL`), `PersonalityDoc` (`personality_doc`: `id Integer PK autoincrement`, `trainer_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `version_number Integer NOT NULL`, `encrypted_body EncryptedBlob NOT NULL`, `is_active Boolean NOT NULL default=True index`, `created_at UTCDateTime NOT NULL`) e `InterviewTopic` (`interview_topics`: `id Integer PK autoincrement`, `trainer_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `category String(64) NOT NULL index`, `prompt_title String(255) NOT NULL`, `is_covered Boolean NOT NULL default=False`, `covered_at UTCDateTime NULLABLE`, `display_order Integer NOT NULL default=0`) en `app/models/knowledge.py` y migración Alembic en `migrations/versions/0003_knowledge_base_and_audio.py`
- [X] T042 [P] [US4] Crear esquemas Pydantic para creación/edición de entradas, filtros de búsqueda, versionado de documento de personalidad, temas de entrevista y parámetros de exportación en `app/schemas/knowledge.py`
- [X] T043 [US4] Implementar el servicio de base de conocimiento (cifrado y descifrado con la DEK del entrenador, búsqueda y filtrado en memoria en servidor, gestión del catálogo inicial de temas de entrevista, borrado seguro de entrada + archivo de audio en disco y generador de exportación en streaming a `JSONL` y `TXT` con registro en `audit_log`) en `app/services/knowledge.py`
- [X] T044 [US4] Implementar el servicio de audio (validación de límite de tamaño y verificación de *magic bytes* MIME para `audio/webm`, `audio/ogg` y `audio/wav`, escritura cifrada con AES-256-GCM en disco y cola en segundo plano con `faster-whisper` operando sobre búfer en memoria `BytesIO` sin archivos temporales en claro) en `app/services/audio.py`
- [X] T045 [US4] Implementar los endpoints del entrenador (`GET/POST /trainer/entries`, `PUT/DELETE /trainer/entries/{id}`, `POST /trainer/audio/upload`, `GET/POST /trainer/personality`, `GET /trainer/interview`, `POST /trainer/export`) protegidos con `require_role("entrenador")` en `app/routers/trainer.py`
- [X] T046 [P] [US4] Crear plantillas Jinja2 del panel del entrenador (entradas, grabadora de voz, personalidad y modo entrevista) y script local de grabación con `MediaRecorder` en `app/templates/trainer/entries.html`, `app/templates/trainer/audio.html`, `app/templates/trainer/personality.html`, `app/templates/trainer/interview.html` y `app/static/js/audio.js`

**Checkpoint**: Parte 4 (Base de conocimiento cifrada, voz con `faster-whisper`, entrevista y exportación) completa y desplegable.

---

## Phase 7: User Story 5 - Conversación de Amigos con la Simulación, Streaming SSE y Búsqueda Web Etiquetada (Priority: P2)

**Goal**: Interfaz de conversación para amigos con respuestas del LLM en streaming SSE integrado con HTMX, construcción de prompt con personalidad + `RetrievalStrategy` + historial, instrucciones de hablar en primera persona sin inventar hechos biográficos, búsqueda web como herramienta cuyos resultados se envuelven en código con `[Información externa]` e indicador visual en la UI, aviso de simulación añadido siempre por código, defensa contra inyección de prompt, límites diarios de tokens y aislamiento criptográfico con la DEK de cada amigo.

**Independent Test**: Configurar el proveedor LLM como entrenador, iniciar conversaciones con dos cuentas de `amigo` distintas, comprobar el streaming SSE con un LLM simulado, verificar que cada respuesta lleva el aviso de simulación añadido por código, que las búsquedas web se etiquetan con `[Información externa]`, y que un amigo no puede leer conversaciones de otro amigo ni acceder a la base de conocimiento del entrenador.

### Tests for User Story 5 ⚠️

- [X] T047 [P] [US5] Escribir pruebas unitarias de defensa contra inyección de prompt, saneamiento y truncado de resultados externos, envoltura determinista con `[Información externa]` e inyección por código del aviso de simulación en `tests/unit/test_prompt_guard.py`
- [X] T048 [P] [US5] Escribir pruebas de integración con LLM simulado validando streaming SSE, aislamiento criptográfico de conversaciones entre amigos, imposibilidad de que un amigo vea la base de conocimiento, etiquetado de búsqueda web y tope diario de tokens en `tests/integration/test_chat_llm.py`

### Implementation for User Story 5

- [X] T049 [P] [US5] Crear modelos `Conversation` (`conversations`: `id Integer PK autoincrement`, `friend_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `encrypted_title EncryptedBlob NOT NULL`, `created_at UTCDateTime NOT NULL`, `updated_at UTCDateTime NOT NULL index`), `Message` (`messages`: `id Integer PK autoincrement`, `conversation_id Integer FK(conversations.id, ON DELETE CASCADE) NOT NULL index`, `friend_id Integer FK(users.id, ON DELETE CASCADE) NOT NULL index`, `sender_role String(16) NOT NULL` con valores `"user"|"simulation"`, `encrypted_content EncryptedBlob NOT NULL`, `used_web_search Boolean NOT NULL default=False`, `simulation_notice_shown Boolean NOT NULL default=True`, `token_count Integer NOT NULL default=0`, `created_at UTCDateTime NOT NULL index`) y `LLMSettings` (`llm_settings`: `id Integer PK autoincrement`, `provider_name String(32) NOT NULL default="ollama"`, `base_url String(255) NOT NULL`, `model_name String(120) NOT NULL`, `encrypted_api_key EncryptedBlob NULLABLE`, `context_entries_limit Integer NOT NULL default=10`, `daily_token_limit_per_user Integer NOT NULL default=25000`, `web_search_enabled Boolean NOT NULL default=False`, `web_search_url String(255) NULLABLE`, `updated_at UTCDateTime NOT NULL`) en `app/models/conversation.py` y migración Alembic en `migrations/versions/0004_conversations_and_llm_settings.py`
- [X] T050 [P] [US5] Crear esquemas Pydantic para creación de conversaciones, envío de mensajes, eventos SSE y actualización de `llm_settings` (garantizando que `encrypted_api_key` jamás se serialice de vuelta al cliente) en `app/schemas/conversation.py`
- [X] T051 [P] [US5] Implementar el protocolo `RetrievalStrategy` y su implementación por defecto `RecentEntriesStrategy` (recuperando las últimas $N$ entradas confirmadas del entrenador descifradas en memoria) en `app/services/retrieval.py`
- [X] T052 [P] [US5] Implementar el servicio de búsqueda web intercambiable (ej. SearXNG) que sanea resultados, limita su longitud y envuelve obligatoriamente cada resultado en código con la etiqueta fija `"[Información externa]"` en `app/services/web_search.py`
- [X] T053 [US5] Implementar el servicio LLM con cliente compatible con OpenAI (`httpx` asíncrono con timeout y reintentos acotados), ensamblado de prompt con delimitación anti-inyección, ejecución de tool-calling de búsqueda web, control de cuota diaria de tokens por usuario, inyección por código del aviso de simulación y cifrado de mensajes con la DEK del amigo en `app/services/llm.py`
- [X] T054 [US5] Implementar endpoints de conversación del amigo (`GET/POST /friend/conversations`, `GET /friend/conversations/{id}`, `POST /friend/conversations/{id}/messages`, `GET /friend/conversations/{id}/stream`) en `app/routers/friend.py` y pantalla de ajustes LLM del entrenador (`GET/POST /trainer/llm-settings`) en `app/routers/trainer.py`
- [X] T055 [P] [US5] Crear plantillas Jinja2 de chat del amigo (con insignia visible de `[Información externa]` y aviso fijo de simulación), plantilla de ajustes LLM del entrenador y script SSE para HTMX en `app/templates/friend/chat_list.html`, `app/templates/friend/chat_room.html`, `app/templates/friend/message_partial.html`, `app/templates/trainer/llm_settings.html` y `app/static/js/chat_sse.js`

**Checkpoint**: Parte 5 (Conversaciones cifradas de amigos con el LLM, SSE y búsqueda web etiquetada) completa y desplegable.

---

## Phase 8: User Story 6 - Modo Póstumo con Albacea y Herramientas CLI de Portabilidad y Continuidad (Priority: P3)

**Goal**: Gestión de albaceas (`executors`), protocolo auditado de activación del modo `póstumo` con plazo de espera y notificaciones al entrenador y contactos, bloqueo en solo lectura de la base de conocimiento al activarse el modo `póstumo`, indicación en las conversaciones de que el entrenador ha fallecido, herramientas CLI (`export-all`, `import-all`, `migrate-db` SQLite ↔ MariaDB con recuentos y checksums SHA-256), copias de seguridad cifradas y Documento de Continuidad (`README.md`).

**Independent Test**: Simular la solicitud de modo póstumo por el albacea verificando que no puede confirmarse antes del plazo y que el entrenador puede cancelarla; confirmar el paso a modo `póstumo` tras el plazo y verificar que toda escritura sobre la base de conocimiento devuelve `403 Forbidden`; ejecutar los tests de ida y vuelta SQLite → MariaDB con `migrate-db` y restauración desde copia cifrada con `export-all`/`import-all` sin pérdida de datos.

### Tests for User Story 6 ⚠️

- [X] T056 [P] [US6] Escribir pruebas de integración para el protocolo de activación del modo póstumo (intento de confirmación prematura, cancelación por el entrenador, activación tras el plazo, bloqueo en solo lectura de la base de conocimiento y permisos del albacea sobre invitaciones) en `tests/integration/test_succession.py`
- [X] T057 [P] [US6] Escribir pruebas de portabilidad extremo a extremo verificando migración sin pérdida SQLite → MariaDB (`migrate-db` con recuentos y checksums SHA-256) y ciclo completo de copia de seguridad cifrada y restauración (`export-all` y `import-all`) en `tests/portability/test_migration_backup.py`

### Implementation for User Story 6

- [X] T058 [P] [US6] Crear modelos `SystemState` (`system_state`: `id Integer PK`, `mode String(24) NOT NULL default="activo"` con valores `"activo"|"transicion_pendiente"|"postumo"`, `cooldown_hours Integer NOT NULL default=72`, `transition_requested_at UTCDateTime NULLABLE`, `transition_confirmable_after UTCDateTime NULLABLE`, `posthumous_activated_at UTCDateTime NULLABLE`, `updated_at UTCDateTime NOT NULL`), `Executor` (`executors`: `id Integer PK autoincrement`, `user_id Integer FK(users.id, ON DELETE CASCADE) UNIQUE NOT NULL`, `designated_by_id Integer FK(users.id) NOT NULL`, `notification_contacts Text NULLABLE`, `is_active Boolean NOT NULL default=True`, `created_at UTCDateTime NOT NULL`) y `SuccessionEvent` (`succession_events`: `id Integer PK autoincrement`, `actor_user_id Integer FK(users.id) NOT NULL`, `event_type String(40) NOT NULL index` con valores `"REQUESTED"|"NOTIFIED"|"CANCELLED_BY_TRAINER"|"CONFIRMED_POSTHUMOUS"`, `notes String(255) NULLABLE`, `created_at UTCDateTime NOT NULL index`) en `app/models/succession.py` y migración Alembic en `migrations/versions/0005_succession_and_posthumous_mode.py`
- [X] T059 [P] [US6] Crear esquemas Pydantic para designación de albacea, solicitud/cancelación/confirmación de transición póstuma y manifiesto de portabilidad con checksums en `app/schemas/succession.py`
- [X] T060 [US6] Implementar el servicio de sucesión (máquina de estados `activo -> transicion_pendiente -> postumo`, cálculo de `transition_confirmable_after`, envío de avisos por correo al entrenador y contactos, cancelación inmediata si el entrenador interactúa, y registro de cada paso en `succession_events` y `audit_log`) en `app/services/succession.py`
- [X] T061 [US6] Actualizar `app/routers/dependencies.py`, `app/routers/trainer.py` y `app/services/llm.py` para imponer solo lectura estricto sobre la base de conocimiento cuando `system_state.mode == "postumo"`, habilitar la gestión de invitaciones/accesos para el albacea y añadir en cada conversación la indicación de que el entrenador ha fallecido
- [X] T062 [US6] Implementar endpoints de sucesión (`GET /executor/panel`, `POST /executor/request-transition`, `POST /executor/cancel-transition`, `POST /executor/confirm-posthumous`) en `app/routers/executor.py` y gestión de albaceas por el entrenador en `app/routers/trainer.py`
- [X] T063 [US6] Implementar el servicio de portabilidad y copias de seguridad cifradas (empaquetado cifrado AES-256-GCM derivado con Argon2id para `export-all` e `import-all`, y transferencia transaccional SQLAlchemy entre SQLite y MySQL/MariaDB con verificación de recuentos y checksums SHA-256 para `migrate-db`) en `app/services/portability.py` y registrar los subcomandos CLI en `app/cli.py`
- [X] T064 [P] [US6] Crear plantillas Jinja2 del panel de albacea, gestión de albaceas del entrenador y correo de notificación de transición en `app/templates/executor/succession_panel.html`, `app/templates/trainer/executors.html` y `app/templates/emails/succession_notice.txt`

**Checkpoint**: Parte 6 (Modo póstumo, albacea, copias cifradas y migración SQLite ↔ MariaDB) completa y desplegable.

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Documentación de continuidad, pipeline de integración continua dual (SQLite + MariaDB) y verificación final de cobertura y seguridad.

- [X] T065 [P] Redactar el Documento de Continuidad (procedimiento detallado para recuperar la KEK, restaurar desde copia cifrada `export-all`, migrar entre SQLite y MariaDB y sustituir proveedores de LLM/SMTP/búsqueda) en `README.md`
- [X] T066 [P] Configurar el flujo de CI para ejecutar `ruff`, `mypy`, `bandit`, `pip-audit` y la suite completa de `pytest` (con exigencia de cobertura $\ge 80\%$ en seguridad) tanto contra SQLite como contra un servicio contenedorizado MariaDB `utf8mb4` en `.github/workflows/ci.yml`
- [X] T067 Ejecutar la validación integral definida en `specs/001-role-based-access/quickstart.md` verificando todos los escenarios de las Partes 1 a 6 en `tests/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: Sin dependencias; comienza de inmediato.
- **Phase 2 (Foundational - Parte 1)**: Depende de Phase 1; **BLOQUEA** todas las historias de usuario (`US1`–`US6`).
- **Phase 3 (`US1` - Login 2FA, ALTCHA, OTP, Bloqueo)**: Depende de Phase 2.
- **Phase 4 (`US2` - Roles, Invitaciones, Recuperación, CSRF/Sesiones)**: Depende de `US1` (completa la **Parte 2**).
- **Phase 5 (`US3` - Passkeys WebAuthn)**: Depende de `US1`/`US2` (constituye la **Parte 3**).
- **Phase 6 (`US4` - Base de Conocimiento, Voz y Entrevista)**: Depende de `US2` (constituye la **Parte 4**; puede ejecutarse en paralelo con `US3`).
- **Phase 7 (`US5` - Conversación de Amigos, SSE y Búsqueda Web)**: Depende de `US4` (constituye la **Parte 5**).
- **Phase 8 (`US6` - Modo Póstumo, Albacea y Portabilidad CLI)**: Depende de `US4` y `US5` (constituye la **Parte 6**).
- **Phase 9 (Polish & CI)**: Depende de completar las fases anteriores.

### Parallel Opportunities

- En **Phase 1**: `T003`, `T004`, `T005` y `T006` pueden ejecutarse en paralelo.
- En **Phase 2**: `T011`, `T012`, `T013`, `T014`, `T016` y `T018` pueden ejecutarse en paralelo.
- Una vez completada **Phase 4 (`US2`)**, **Phase 5 (`US3` - WebAuthn)** y **Phase 6 (`US4` - Base de Conocimiento)** pueden desarrollarse en paralelo porque operan sobre modelos, servicios y rutas independientes (`webauthn.py` vs `knowledge.py`/`audio.py`).
- Dentro de cada historia de usuario, las tareas de pruebas (`[P]`), modelos/esquemas (`[P]`) y plantillas/estáticos (`[P]`) pueden ejecutarse en paralelo.

---

## Parallel Example: User Story 4 (Base de Conocimiento y Voz)

```bash
# 1. Lanzar pruebas e implementación de modelos/esquemas en paralelo:
Task T040: "Escribir pruebas de integración en tests/integration/test_knowledge.py"
Task T041: "Crear modelos Entry, AudioFile, PersonalityDoc e InterviewTopic en app/models/knowledge.py"
Task T042: "Crear esquemas Pydantic en app/schemas/knowledge.py"

# 2. Implementar servicios y endpoints:
Task T043: "Implementar servicio de base de conocimiento en app/services/knowledge.py"
Task T044: "Implementar servicio de audio y cola faster-whisper en app/services/audio.py"
Task T045: "Implementar endpoints del entrenador en app/routers/trainer.py"

# 3. Construir interfaz local sin CDN:
Task T046: "Crear plantillas Jinja2 y script MediaRecorder en app/static/js/audio.js"
```

---

## Implementation Strategy

### Incremental Delivery (6 Partes Desplegables)

1. **Incremento 1 (Phases 1 + 2)**: Configuración `.env` *fail-fast*, motor dual SQLite/MariaDB, cifrado AES-256-GCM y middlewares de seguridad.
2. **Incremento 2 (Phases 3 + 4 — MVP de Acceso Seguro)**: Login con Argon2id + ALTCHA + OTP email, sesiones, invitaciones de 256 bits, códigos de recuperación y autorización por rol.
3. **Incremento 3 (Phase 5)**: Passkeys WebAuthn (`py_webauthn`) como segundo factor y gestión en perfil.
4. **Incremento 4 (Phase 6)**: Base de conocimiento cifrada del entrenador, grabación y transcripción local con `faster-whisper`, modo entrevista y exportación `JSONL`/`TXT`.
5. **Incremento 5 (Phase 7)**: Conversación de amigos con simulación LLM en streaming SSE, búsqueda web etiquetada con `[Información externa]` y aviso de simulación inyectado por código.
6. **Incremento 6 (Phases 8 + 9)**: Modo póstumo con albacea, CLI de migración SQLite ↔ MariaDB y copias cifradas (`export-all`/`import-all`), y Documento de Continuidad.
