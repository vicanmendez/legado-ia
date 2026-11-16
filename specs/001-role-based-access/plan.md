# Implementation Plan: Plataforma legado-ia (Acceso, Conocimiento, Conversación y Continuidad Póstuma)

**Branch**: `001-role-based-access` | **Date**: 2026-11-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-role-based-access/spec.md` y definición arquitectónica en 6 incrementos funcionales.

## Summary

Construcción incremental de **legado-ia**, una aplicación web autoalojada que preserva y simula la personalidad, el lenguaje y el conocimiento de una persona (`ENTRENADOR`) para que sus allegados (`AMIGO`) conversen con dicha simulación, incluso tras su fallecimiento (modo `póstumo` gestionado por un `ALBACEA` / `executor`).

El diseño técnico se articula en **6 partes incrementales y desplegables de forma autónoma**:
1. **Base transversal, configuración y base de datos dual**: FastAPI + Jinja2/HTMX local (`/static`), validación estricta de entorno con `pydantic-settings` (*fail-fast*), cifrado por sobre AES-256-GCM (KEK externa + DEK por usuario), cabeceras de seguridad (`CSP: 'self'`), CSRF y portabilidad total entre SQLite (WAL) y MySQL/MariaDB (`utf8mb4`, TLS, Alembic `render_as_batch=True`).
2. **Autenticación en dos pasos, invitaciones y control de roles**: Login con Argon2id + captcha ALTCHA validado en servidor con HMAC + segundo factor por código OTP de 6 dígitos por email (`aiosmtplib`), sesiones en servidor con estado pendiente de 2FA, bloqueo progresivo (`slowapi` + contador en BD), invitaciones de un solo uso y códigos de recuperación.
3. **Passkeys WebAuthn**: Segundo factor alternativo sin fricción mediante `py_webauthn` (`userVerification=required`), control de contador de firmas contra credenciales clonadas y gestión desde el perfil.
4. **Base de conocimiento, voz y modo entrevista del entrenador**: Entradas de texto cifradas, documento de personalidad versionado, grabación de audio en navegador (`MediaRecorder`) cifrada en disco y transcrita en segundo plano con `faster-whisper`, entrevista guiada y exportación en streaming (`JSONL`/`TXT`).
5. **Conversación con amigos, búsqueda web y defensa ante prompt injection**: Cliente LLM compatible con OpenAI (`httpx`, Ollama por defecto / OpenRouter opcional), streaming SSE con HTMX, estrategia `RetrievalStrategy` reemplazable, herramienta de búsqueda web etiquetada en código como `[Información externa]`, aviso permanente de simulación inyectado por código y aislamiento criptográfico de cada conversación con la DEK del amigo.
6. **Modo póstumo, albacea y portabilidad/continuidad**: Protocolo auditado de transición a estado `póstumo` con plazo de espera y notificaciones, bloqueo en solo lectura de la base de conocimiento, gestión de accesos por el albacea, herramientas CLI (`export-all`, `import-all`, `migrate-db` SQLite ↔ MariaDB con verificación de checksums) y copias de seguridad cifradas.

## Technical Context

**Language/Version**: Python 3.12 (gestión de paquetes y entorno con `uv`, `uv.lock` con versiones fijadas y verificación de hashes)

**Primary Dependencies**:
- Web y plantillas: `fastapi`, `uvicorn`, `jinja2`, `python-multipart`
- Frontend estático (`/static`): `htmx.min.js`, CSS propio y JS nativo mínimo (`navigator.credentials`, `MediaRecorder`, `EventSource`/SSE), sin CDN ni `npm`
- Configuración y validación: `pydantic` (v2), `pydantic-settings`
- Base de datos y migraciones: `sqlalchemy` (2.x declarativo `Mapped`/`mapped_column`), `alembic` (`render_as_batch=True`), `pymysql`, `sqlite3` (stdlib)
- Criptografía y autenticación: `cryptography` (AES-256-GCM), `argon2-cffi` (Argon2id), `py_webauthn`, ALTCHA (validación HMAC en servidor)
- Red, correo y límites: `aiosmtplib`, `httpx` (cliente LLM y búsqueda web), `slowapi` (rate limiting)
- Audio / IA local: `faster-whisper` (transcripción local voz a texto)

**Storage**:
- Relacional dual: SQLite 3 (`PRAGMA foreign_keys=ON`, `journal_mode=WAL`) y MySQL/MariaDB (`utf8mb4`, `LONGBLOB` variante para `LargeBinary`, TLS cuando el host no es local mediante `DB_SSL_CA`).
- Sistema de archivos local: almacenamiento de archivos de audio cifrados con AES-256-GCM en ruta configurable por `.env` (referenciados en BD por ruta relativa, hash SHA-256 y tamaño).

**Testing**: `pytest`, `pytest-asyncio`, `httpx` (`TestClient`), ejecutados en CI contra SQLite y contra contenedor MariaDB. Calidad y seguridad: `ruff`, `mypy`, `bandit`, `pip-audit`. Cobertura mínima del 80 % en módulos de seguridad.

**Target Platform**: Servidor Linux en contenedor Docker (usuario sin privilegios `non-root`, secretos inyectados vía Docker secrets, orquestado con `docker-compose.yml` junto con MariaDB y Ollama opcionales).

**Project Type**: Aplicación web monolítica modular con interfaz renderizada en servidor (Jinja2 + HTMX) y CLI de administración (`app/cli.py`).

**Performance Goals**:
- Tiempo de respuesta en validación de sesión y rutas autenticadas < 100 ms (p95, excluyendo inferencia LLM y hashing Argon2id intencionalmente costoso).
- Inicio de streaming SSE de respuesta del LLM < 2 s tras envío del mensaje (dependiente del proveedor LLM).
- Exportación e importación de base de conocimiento en streaming con consumo de memoria constante $O(1)$ respecto al número de entradas.

**Constraints**:
- Cero dependencias de CDN o scripts remotos; `Content-Security-Policy` estricto con `'self'` (sin `'unsafe-inline'`).
- Ningún texto sensible (recuerdos, personalidad, mensajes, claves de API) almacenado en claro en base de datos ni en disco.
- Cero SQL específico de motor; prohibición total de consultas en crudo o concatenación de URLs de conexión.
- Arranque *fail-fast* en producción si falta cualquier secreto obligatorio, si `APP_SECRET_KEY` tiene entropía insuficiente (< 32 bytes), si `APP_BASE_URL` no usa `https://`, o si faltan credenciales del motor de BD seleccionado.

**Scale/Scope**: Instancia personal/familiar por entrenador (1 entrenador, 1–2 albaceas, decenas de amigos autorizados, miles de entradas de conocimiento y archivos de audio, decenas de miles de mensajes cifrados).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principio Constitucional | Estado Pre-Diseño | Verificación en el Plan Técnico | Estado Post-Diseño |
|--------------------------|-------------------|---------------------------------|--------------------|
| **I. Seguridad por Diseño** | PASS | Dependencias FastAPI `require_user` y `require_role` deniegan por defecto; validación Pydantic en toda entrada; CSRF por sesión en formularios y cabecera `X-CSRF-Token` en HTMX; cabeceras HSTS, X-Frame-Options=DENY, CSP `'self'`. | PASS |
| **II. Cifrado en Reposo** | PASS | Cifrado por sobre AES-256-GCM (`cryptography`): KEK leída de `ENCRYPTION_KEK_FILE` (Docker secret) envuelve la DEK de cada usuario. Entradas, personalidad y audios cifrados con DEK del entrenador; mensajes cifrados con DEK del amigo; claves API con KEK/DEK. Contraseñas con Argon2id (`argon2-cffi`). | PASS |
| **III. Autenticación Fuerte** | PASS | Paso 1: usuario + contraseña Argon2id + captcha ALTCHA con HMAC y antirrepetición. Paso 2: OTP de 6 dígitos por email (caducidad 10 min, máx. 5 intentos, guardado como hash) o Passkey WebAuthn (`userVerification=required`). Registro solo por invitación de 256 bits de un solo uso. Códigos de recuperación de un solo uso. | PASS |
| **IV. Auditoría** | PASS | Tabla `audit_log` registra logins, fallos, bloqueos, invitaciones, uso de recuperación, cambios de passkeys, exportaciones y cada paso del protocolo póstumo sin incluir jamás secretos ni contenido en claro. | PASS |
| **V. Mínima Dependencia de Terceros** | PASS | SMTP genérico (`aiosmtplib`), LLM compatible con OpenAI (`httpx`), búsqueda web tras interfaz abstracta, ALTCHA local, HTMX y estilos servidos desde `/static`. CSP `'self'`. | PASS |
| **VI. Configuración por .env** | PASS | `app/config.py` con `pydantic-settings` valida todas las variables al arrancar y aborta en producción ante cualquier ausencia o debilidad. `.env.example` versionado; `.env` excluido. | PASS |
| **VII. Portabilidad de BD** | PASS | SQLAlchemy 2.x `Mapped`/`mapped_column`, `String(n)` explícito, `LargeBinary().with_variant(LONGBLOB, "mysql", "mariadb")`, fechas UTC, `URL.create()`, SQLite WAL + FK y MariaDB `utf8mb4` + TLS. Alembic con `render_as_batch=True`. | PASS |
| **VIII. Portabilidad de Datos** | PASS | Exportación en streaming a `JSONL` y `TXT`, más comando CLI `export-all` / `import-all` y `migrate-db`. Proveedor LLM intercambiable (Ollama por defecto, OpenRouter opcional). | PASS |
| **IX. Transparencia** | PASS | El aviso de simulación (y el estado póstumo cuando aplica) se inyecta por código en cada respuesta y vista; los resultados de búsqueda web se envuelven en código con `[Información externa]` y muestran indicador visual en la UI. | PASS |
| **X. Pruebas Obligatorias** | PASS | Suite `pytest` obligatoria (>80 % cobertura en seguridad) ejecutada en SQLite y MariaDB validando bypass 2FA, RBAC, cifrado en disco/BD, WebAuthn replay, prompt injection y migración de datos. | PASS |
| **XI. Incrementalidad** | PASS | Las 6 partes están diseñadas como incrementos verticales autónomos y desplegables en orden secuencial. | PASS |

*Resultado de la puerta constitucional*: **APROBADO (0 violaciones)**.

## Project Structure

### Documentation (this feature)

```text
specs/001-role-based-access/
├── plan.md              # Este documento (salida de /speckit-plan)
├── research.md          # Decisiones técnicas y patrones (Fase 0)
├── data-model.md        # Modelo de datos completo Partes 1–6 (Fase 1)
├── quickstart.md        # Guía de validación y ejecución (Fase 1)
├── contracts/           # Contratos de interfaz HTTP/HTMX y CLI (Fase 1)
│   ├── http-endpoints.md
│   └── cli-commands.md
└── tasks.md             # Lista de tareas ordenadas (salida futura de /speckit-tasks)
```

### Source Code (repository root)

```text
app/
├── __init__.py
├── main.py                  # Fábrica de la app FastAPI, middlewares (CSP, HSTS, CSRF, sesiones) y routers
├── config.py                # Settings con pydantic-settings y validadores fail-fast de producción
├── cli.py                   # Comandos: init-trainer, export-all, import-all, migrate-db, backup, restore
├── db/
│   ├── __init__.py
│   ├── base.py              # DeclarativeBase, tipos personalizados (EncryptedBytes, UTCDateTime)
│   └── session.py           # URL.create(), creación de engine (SQLite pragmas / MySQL SSL), get_db
├── models/
│   ├── __init__.py
│   ├── user.py              # User, UserKey, Session, OTPCode, Invitation, RecoveryCode
│   ├── webauthn.py          # WebAuthnCredential
│   ├── knowledge.py         # Entry, AudioFile, PersonalityDoc, InterviewTopic
│   ├── conversation.py      # Conversation, Message, LLMSettings, TokenUsage
│   ├── succession.py        # Executor, SuccessionEvent, SystemState
│   └── audit.py             # AuditLog
├── schemas/
│   ├── __init__.py
│   ├── auth.py              # Esquemas de login, OTP, invitación, registro y recuperación
│   ├── webauthn.py          # Esquemas de registro y autenticación WebAuthn
│   ├── knowledge.py         # Esquemas de entradas, subida de audio, personalidad y entrevista
│   ├── conversation.py      # Esquemas de mensajes, configuración LLM y resultados de herramientas
│   └── succession.py        # Esquemas de designación de albacea y transición póstuma
├── services/
│   ├── __init__.py
│   ├── crypto.py            # AES-256-GCM envelope encryption (KEK/DEK), Argon2id, tokens y hashes
│   ├── auth.py              # Flujo 2 pasos, sesiones, backoff exponencial, códigos de recuperación
│   ├── altcha.py            # Generación de desafío HMAC y verificación con antirrepetición
│   ├── webauthn.py          # Integración py_webauthn, validación de challenge y sign_count
│   ├── email.py             # Envío asíncrono en texto plano con aiosmtplib
│   ├── audit.py             # Registro seguro de eventos sin datos sensibles
│   ├── knowledge.py         # Cifrado/descifrado de entradas, búsqueda en memoria, exportación streaming
│   ├── audio.py             # Validación MIME por magic bytes, cifrado en disco, cola faster-whisper
│   ├── retrieval.py         # Protocolo RetrievalStrategy e implementación RecentEntriesStrategy
│   ├── llm.py               # Cliente OpenAI-compatible (httpx SSE), defensa prompt injection, aviso código
│   ├── web_search.py        # Proveedor intercambiable de búsqueda web y etiquetado [Información externa]
│   ├── succession.py        # Máquina de estados activo -> en_espera -> póstumo y notificaciones
│   └── portability.py       # Exportación/importación empaquetada cifrada y migración SQLite <-> MariaDB
├── routers/
│   ├── __init__.py
│   ├── dependencies.py      # require_user, require_role, verify_csrf, check_system_mode
│   ├── auth.py              # Login paso 1 y 2, ALTCHA, logout, registro por invitación, recuperación
│   ├── webauthn.py          # Opciones y verificación de passkeys, gestión en perfil
│   ├── trainer.py           # Panel del entrenador: entradas, audio, personalidad, entrevista, invitaciones, LLM
│   ├── friend.py            # Panel del amigo: conversaciones, envío de mensajes y streaming SSE
│   └── executor.py          # Panel de albacea y activación/gestión del modo póstumo
├── templates/
│   ├── base.html            # Layout común con cabeceras meta, indicador de simulación y estado póstumo
│   ├── auth/                # login.html, verify_2fa.html, register_invite.html, recovery_codes.html
│   ├── profile/             # security.html (passkeys y regeneración de códigos de recuperación)
│   ├── trainer/             # dashboard.html, entries.html, audio.html, personality.html, interview.html, invitations.html, llm_settings.html, executors.html
│   ├── friend/              # chat_list.html, chat_room.html, message_partial.html
│   ├── executor/            # succession_panel.html
│   └── emails/              # otp_code.txt, invitation.txt, succession_notice.txt
└── static/
    ├── vendor/
    │   └── htmx.min.js      # HTMX versionado localmente
    ├── css/
    │   └── main.css         # Estilos propios sin dependencias externas
    └── js/
        ├── csrf.js          # Inyección de cabecera X-CSRF-Token en peticiones HTMX
        ├── altcha.js        # Resolución local del desafío proof-of-work ALTCHA
        ├── webauthn.js      # Envoltorio mínimo sobre navigator.credentials.create / .get
        ├── audio.js         # Grabación con MediaRecorder y subida por formulario/HTMX
        └── chat_sse.js      # Conexión SSE para recepción de fragmentos de respuesta del LLM

migrations/
├── env.py                   # Configurado con render_as_batch=True y metadatos de app.db.base
├── script.py.mako
└── versions/                # Revisiones incrementales por cada parte del proyecto

tests/
├── conftest.py              # Fixtures parametrizadas para SQLite (memoria/archivo) y MariaDB, cliente HTTP y mocks
├── unit/
│   ├── test_config.py       # Validación fail-fast de .env en producción
│   ├── test_crypto.py       # Cifrado por sobre AES-256-GCM, rotación y Argon2id
│   ├── test_altcha.py       # Verificación HMAC y bloqueo de replay en ALTCHA
│   └── test_prompt_guard.py # Sanitización, etiquetado [Información externa] y aviso de simulación
├── integration/
│   ├── test_auth_2fa.py     # Flujo completo login, bypass 2FA, expiración OTP, enumeración, fuerza bruta
│   ├── test_rbac_csrf.py    # Aislamiento estricto amigo vs entrenador y protección CSRF
│   ├── test_webauthn.py     # Registro, login passkey, detección de clonación (sign_count) y replay
│   ├── test_knowledge.py    # Entradas, audio cifrado, verificación de ausencia de texto claro en archivo SQLite
│   ├── test_chat_llm.py     # Conversación cifrada por amigo, SSE, tool calling web search y límites de tokens
│   └── test_succession.py   # Activación póstuma, modo solo lectura y abuso del procedimiento
└── portability/
    └── test_migration_backup.py # Ida y vuelta SQLite -> MariaDB sin pérdida y restauración de backup cifrado

.env.example
Dockerfile
docker-compose.yml
pyproject.toml
uv.lock
README.md                    # Incluye el Documento de Continuidad (recuperación de KEK, restauración y cambio de proveedor)
```

**Structure Decision**: Se selecciona una arquitectura monolítica modular bajo `app/` con plantillas Jinja2 y activos estáticos autoalojados en `app/static/`, acompañada de `migrations/` (Alembic) y `tests/` divididos en pruebas unitarias, de integración y de portabilidad entre motores. Esta estructura refleja exactamente la organización especificada y evita cualquier complejidad de compilación frontend (`npm`/bundlers), garantizando el cumplimiento estricto de `CSP: default-src 'self'`.

## Complexity Tracking

> No existen violaciones a la Constitución que requieran justificación. Todos los componentes responden directamente a los 11 principios constitucionales.
