# Phase 1 Data Model: Esquema Relacional Portable (SQLite & MySQL/MariaDB)

**Feature**: `001-role-based-access` (Modelo completo Partes 1–6)
**Date**: 2026-11-16

---

## Convenciones Globales de Esquema (SQLAlchemy 2.x)

- **Declaración**: Estilo `DeclarativeBase` con anotaciones `Mapped[T]` y `mapped_column(...)`.
- **Cadenas de longitud acotada**: Todo campo `String(n)` especifica `n` explícitamente para compatibilidad de índices en MySQL/MariaDB (`utf8mb4`).
- **Datos cifrados (`EncryptedBlob`)**: Tipo `LargeBinary().with_variant(LONGBLOB(), "mysql", "mariadb")`. Formato binario estándar: `0x01 (1B version) || nonce (12B) || ciphertext || tag (16B)` cifrado con AES-256-GCM y AAD contextual (`"{tabla}:{owner_id}"`).
- **Fechas y horas (`UTCDateTime`)**: `DateTime(timezone=True)` envuelto en `TypeDecorator` que fuerza `timezone.utc` al persistir y recuperar en SQLite y MariaDB.
- **Migraciones**: Alembic configurado con `render_as_batch=True`.

---

## 1. Núcleo de Usuarios, Claves, Sesiones y Autenticación (Partes 1 y 2)

### `users`
Representa a las personas registradas en el sistema (`entrenador`, `amigo` o `albacea`).

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno del usuario |
| `username` | `String(64)` | `UNIQUE, NOT NULL, index` | Nombre de usuario único normalizado |
| `email` | `String(255)` | `UNIQUE, NOT NULL, index` | Dirección de correo para notificaciones y OTP |
| `password_hash` | `String(255)` | `NOT NULL` | Hash Argon2id (`argon2-cffi`) |
| `role` | `String(20)` | `NOT NULL, index` | Valores: `"entrenador"`, `"amigo"`, `"albacea"` |
| `status` | `String(20)` | `NOT NULL, default="active"` | Valores: `"active"`, `"disabled"`, `"locked"` |
| `failed_attempts` | `Integer` | `NOT NULL, default=0` | Contador de fallos consecutivos de autenticación |
| `locked_until` | `UTCDateTime` | `NULLABLE` | Marca temporal UTC hasta la que dura el bloqueo progresivo |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de alta |
| `updated_at` | `UTCDateTime` | `NOT NULL` | Última actualización |

### `user_keys`
Almacena la clave de datos (DEK) de cada usuario cifrada por sobre (*envelope encryption*) con la KEK maestra externa.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), UNIQUE, NOT NULL` | Propietario de la clave |
| `encrypted_dek` | `EncryptedBlob` | `NOT NULL` | DEK de 256 bits cifrada con la KEK mediante AES-256-GCM |
| `key_version` | `Integer` | `NOT NULL, default=1` | Versión de la KEK empleada |
| `rotated_at` | `UTCDateTime` | `NOT NULL` | Fecha de generación o última rotación |

### `sessions`
Sesiones almacenadas en servidor con soporte de estado intermedio ("pendiente de 2FA") y token CSRF propio.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `session_token_hash` | `String(64)` | `UNIQUE, NOT NULL, index` | SHA-256 del ID aleatorio de 256 bits entregado en cookie |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Usuario propietario de la sesión |
| `is_2fa_verified` | `Boolean` | `NOT NULL, default=False` | `False` tras paso 1; `True` solo tras superar OTP, Passkey o código de recuperación |
| `csrf_token` | `String(64)` | `NOT NULL` | Token CSRF vinculado a la sesión |
| `webauthn_challenge` | `LargeBinary(128)` | `NULLABLE` | Challenge efímero de un solo uso para registro/login WebAuthn |
| `ip_address` | `String(45)` | `NULLABLE` | IP de origen (IPv4/IPv6) |
| `user_agent` | `String(255)` | `NULLABLE` | Resumen acotado del navegador |
| `created_at` | `UTCDateTime` | `NOT NULL` | Inicio de la sesión |
| `last_activity_at` | `UTCDateTime` | `NOT NULL` | Última petición válida (para caducidad por inactividad) |
| `expires_at` | `UTCDateTime` | `NOT NULL, index` | Expiración absoluta o corta (10 min si `is_2fa_verified=False`) |
| `revoked_at` | `UTCDateTime` | `NULLABLE` | Marca de cierre de sesión explícito o invalidación |

### `otp_codes`
Códigos temporales de 6 dígitos para el segundo factor por email (máximo un código activo por usuario).

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Usuario destinatario |
| `code_hash` | `String(255)` | `NOT NULL` | Hash seguro del código de 6 dígitos (nunca en claro) |
| `attempts` | `Integer` | `NOT NULL, default=0` | Intentos fallidos realizados (máximo 5) |
| `expires_at` | `UTCDateTime` | `NOT NULL, index` | Fecha de creación + 10 minutos |
| `consumed_at` | `UTCDateTime` | `NULLABLE` | Fecha en que se usó o invalidó |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de emisión |

### `invitations`
Enlaces de invitación de un solo uso emitidos por el entrenador (o albacea en modo póstumo).

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `token_hash` | `String(64)` | `UNIQUE, NOT NULL, index` | SHA-256 del token aleatorio de 256 bits |
| `target_role` | `String(20)` | `NOT NULL, default="amigo"` | Rol asignado al activar (`"amigo"` o `"albacea"`) |
| `recipient_hint` | `String(120)` | `NULLABLE` | Alias o referencia opcional para el entrenador |
| `created_by_id` | `Integer` | `FK(users.id), NOT NULL` | Usuario que emitió la invitación |
| `used_by_id` | `Integer` | `FK(users.id), NULLABLE` | Usuario creado al consumir la invitación |
| `expires_at` | `UTCDateTime` | `NOT NULL, index` | Fecha límite de validez |
| `used_at` | `UTCDateTime` | `NULLABLE` | Marca de consumo (uso único) |
| `revoked_at` | `UTCDateTime` | `NULLABLE` | Marca de revocación manual |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de creación |

### `recovery_codes`
Códigos de recuperación de un solo uso generados al activar la cuenta.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Usuario propietario |
| `code_hash` | `String(255)` | `NOT NULL` | Hash Argon2id/HMAC del código de recuperación |
| `used_at` | `UTCDateTime` | `NULLABLE` | Fecha de consumo (`NULL` si sigue disponible) |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de generación del lote |

### `altcha_consumed_challenges`
Registro de soluciones ALTCHA ya presentadas para impedir reutilización (*replay*) dentro de la ventana de validez.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `challenge_hash` | `String(64)` | `UNIQUE, NOT NULL, index` | SHA-256 del challenge/firma verificado |
| `expires_at` | `UTCDateTime` | `NOT NULL, index` | Fecha en que expira la ventana del desafío |

---

## 2. Credenciales WebAuthn / Passkeys (Parte 3)

### `webauthn_credentials`
Credenciales FIDO2 / Passkeys registradas por el usuario como segundo factor.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Usuario propietario |
| `credential_id` | `LargeBinary(512)` | `UNIQUE, NOT NULL` | ID binario de la credencial WebAuthn |
| `public_key` | `LargeBinary(1024)` | `NOT NULL` | Clave pública COSE serializada |
| `sign_count` | `Integer` | `NOT NULL, default=0` | Contador de firmas verificado para detectar clonación |
| `device_name` | `String(100)` | `NOT NULL` | Nombre descriptivo asignado por el usuario |
| `transports` | `String(120)` | `NULLABLE` | Lista separada por comas (`internal,hybrid,usb...`) |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de alta |
| `last_used_at` | `UTCDateTime` | `NULLABLE` | Última autenticación exitosa |
| `revoked_at` | `UTCDateTime` | `NULLABLE` | Fecha de revocación o bloqueo por anomalía de contador |

---

## 3. Base de Conocimiento, Voz y Entrevista del Entrenador (Parte 4)

### `entries`
Recuerdos, vivencias y textos del entrenador cifrados con la DEK del entrenador.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador de la entrada |
| `trainer_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Entrenador propietario |
| `topic` | `String(120)` | `NOT NULL, index` | Categoría o tema (ej. `"infancia"`, `"valores"`) |
| `entry_date` | `UTCDateTime` | `NOT NULL, index` | Fecha asociada al recuerdo o entrada |
| `encrypted_content` | `EncryptedBlob` | `NOT NULL` | Texto del recuerdo cifrado con la DEK del entrenador |
| `status` | `String(24)` | `NOT NULL, default="confirmed"` | `"draft_transcription"` o `"confirmed"` |
| `interview_topic_id` | `Integer` | `FK(interview_topics.id, ON DELETE SET NULL), NULLABLE` | Tema de entrevista asociado (si procede) |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de creación |
| `updated_at` | `UTCDateTime` | `NOT NULL` | Última edición |

### `audio_files`
Metadatos de las grabaciones de voz cifradas en disco asociadas a una entrada.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador del audio |
| `entry_id` | `Integer` | `FK(entries.id, ON DELETE CASCADE), UNIQUE, NOT NULL` | Entrada asociada |
| `trainer_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Entrenador propietario |
| `storage_rel_path` | `String(255)` | `UNIQUE, NOT NULL` | Ruta relativa del blob cifrado en disco |
| `mime_type` | `String(64)` | `NOT NULL` | Tipo MIME verificado por contenido (`audio/webm`, `audio/ogg`, `audio/wav`) |
| `sha256_hash` | `String(64)` | `NOT NULL` | Hash SHA-256 del archivo cifrado para verificación de integridad |
| `size_bytes` | `Integer` | `NOT NULL` | Tamaño en bytes |
| `transcription_status` | `String(24)` | `NOT NULL, default="pending"` | `"pending"`, `"processing"`, `"completed"`, `"failed"` |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de subida |

### `personality_doc`
Versiones sucesivas del documento de personalidad, estilo lingüístico y valores del entrenador.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador interno |
| `trainer_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Entrenador propietario |
| `version_number` | `Integer` | `NOT NULL` | Número de versión secuencial (1, 2, 3...) |
| `encrypted_body` | `EncryptedBlob` | `NOT NULL` | Contenido del documento cifrado con la DEK del entrenador |
| `is_active` | `Boolean` | `NOT NULL, default=True, index` | Indica la versión vigente para construcción del prompt |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de guardado de la versión |

### `interview_topics`
Catálogo de preguntas/temas del modo entrevista guiada para ayudar al entrenador a construir su legado.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador del tema |
| `trainer_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Entrenador propietario |
| `category` | `String(64)` | `NOT NULL, index` | Bloque temático (`infancia`, `valores`, `trabajo`, `errores`, `consejos`) |
| `prompt_title` | `String(255)` | `NOT NULL` | Pregunta o consigna de la entrevista |
| `is_covered` | `Boolean` | `NOT NULL, default=False` | Marcado como cubierto cuando existe entrada confirmada |
| `covered_at` | `UTCDateTime` | `NULLABLE` | Fecha en que se completó |
| `display_order` | `Integer` | `NOT NULL, default=0` | Orden de presentación |

---

## 4. Conversaciones de Amigos y Configuración LLM (Parte 5)

### `conversations`
Hilos de conversación privados entre un amigo y la simulación del entrenador.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador de la conversación |
| `friend_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Amigo propietario de la conversación |
| `encrypted_title` | `EncryptedBlob` | `NOT NULL` | Título del hilo cifrado con la DEK del amigo |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de inicio |
| `updated_at` | `UTCDateTime` | `NOT NULL, index` | Fecha del último mensaje |

### `messages`
Mensajes individuales dentro de una conversación, cifrados con la DEK del amigo.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador del mensaje |
| `conversation_id` | `Integer` | `FK(conversations.id, ON DELETE CASCADE), NOT NULL, index` | Conversación a la que pertenece |
| `friend_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), NOT NULL, index` | Propietario para filtrado directo y AAD |
| `sender_role` | `String(16)` | `NOT NULL` | `"user"` (amigo) o `"simulation"` (respuesta de la IA) |
| `encrypted_content` | `EncryptedBlob` | `NOT NULL` | Cuerpo del mensaje cifrado con la DEK del amigo |
| `used_web_search` | `Boolean` | `NOT NULL, default=False` | `True` si la respuesta incorporó `[Información externa]` |
| `simulation_notice_shown` | `Boolean` | `NOT NULL, default=True` | Confirmación de inyección por código del aviso de simulación |
| `token_count` | `Integer` | `NOT NULL, default=0` | Tokens consumidos para control de cuota diaria |
| `created_at` | `UTCDateTime` | `NOT NULL, index` | Marca temporal del mensaje |

### `llm_settings`
Configuración del proveedor de modelo de lenguaje y búsqueda web administrada por el entrenador.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador único (fila activa) |
| `provider_name` | `String(32)` | `NOT NULL, default="ollama"` | `"ollama"`, `"openrouter"`, `"openai_compatible"` |
| `base_url` | `String(255)` | `NOT NULL` | URL base del API compatible con OpenAI |
| `model_name` | `String(120)` | `NOT NULL` | Identificador del modelo (ej. `llama3.1:8b`) |
| `encrypted_api_key` | `EncryptedBlob` | `NULLABLE` | Clave API cifrada con AES-256-GCM (nunca devuelta a la UI) |
| `context_entries_limit` | `Integer` | `NOT NULL, default=10` | Número $N$ de entradas recientes inyectadas en el prompt |
| `daily_token_limit_per_user` | `Integer` | `NOT NULL, default=25000` | Tope diario de tokens por amigo |
| `web_search_enabled` | `Boolean` | `NOT NULL, default=False` | Habilita o deshabilita la herramienta de búsqueda web |
| `web_search_url` | `String(255)` | `NULLABLE` | Endpoint del buscador (ej. instancia SearXNG) |
| `updated_at` | `UTCDateTime` | `NOT NULL` | Última modificación |

---

## 5. Sucesión, Albacea y Estado del Sistema (Parte 6)

### `system_state`
Registro singleton (`id = 1`) que refleja el modo operativo global de la plataforma.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK` | Siempre `1` |
| `mode` | `String(24)` | `NOT NULL, default="activo"` | `"activo"`, `"transicion_pendiente"`, `"postumo"` |
| `cooldown_hours` | `Integer` | `NOT NULL, default=72` | Plazo de espera en horas antes de poder confirmar modo póstumo |
| `transition_requested_at` | `UTCDateTime` | `NULLABLE` | Inicio del plazo de espera |
| `transition_confirmable_after` | `UTCDateTime` | `NULLABLE` | Fecha a partir de la cual el albacea puede confirmar |
| `posthumous_activated_at` | `UTCDateTime` | `NULLABLE` | Fecha definitiva en que entró en modo `postumo` |
| `updated_at` | `UTCDateTime` | `NOT NULL` | Última actualización |

### `executors`
Albaceas designados por el entrenador con permiso para iniciar y gestionar el modo póstumo.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador del albacea |
| `user_id` | `Integer` | `FK(users.id, ON DELETE CASCADE), UNIQUE, NOT NULL` | Cuenta de usuario asociada al albacea |
| `designated_by_id` | `Integer` | `FK(users.id), NOT NULL` | Entrenador que lo designó |
| `notification_contacts` | `Text` | `NULLABLE` | Lista JSON de correos adicionales a avisar al iniciar transición |
| `is_active` | `Boolean` | `NOT NULL, default=True` | Estado de la designación |
| `created_at` | `UTCDateTime` | `NOT NULL` | Fecha de designación |

### `succession_events`
Historial formal de pasos ejecutados en el protocolo de sucesión.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador del evento |
| `actor_user_id` | `Integer` | `FK(users.id), NOT NULL` | Usuario que ejecutó la acción (`albacea` o `entrenador`) |
| `event_type` | `String(40)` | `NOT NULL, index` | `"REQUESTED"`, `"NOTIFIED"`, `"CANCELLED_BY_TRAINER"`, `"CONFIRMED_POSTHUMOUS"` |
| `notes` | `String(255)` | `NULLABLE` | Motivo o referencia no sensible |
| `created_at` | `UTCDateTime` | `NOT NULL, index` | Fecha UTC del paso |

---

## 6. Auditoría Transversal de Seguridad (Partes 1–6)

### `audit_log`
Registro inmutable de eventos de seguridad sin datos sensibles en claro.

| Columna | Tipo SQLAlchemy | Restricciones | Descripción |
|---------|-----------------|---------------|-------------|
| `id` | `Integer` | `PK, autoincrement` | Identificador correlativo |
| `event_code` | `String(64)` | `NOT NULL, index` | Ej. `"AUTH_LOGIN_SUCCESS"`, `"AUTH_2FA_FAIL"`, `"ROLE_DENIED"`, `"KB_EXPORT"`, `"SUCCESSION_REQUEST"` |
| `actor_user_id` | `Integer` | `FK(users.id, ON DELETE SET NULL), NULLABLE, index` | Usuario autenticado o afectado (si se conoce) |
| `ip_address` | `String(45)` | `NULLABLE` | IP de origen |
| `metadata_json` | `Text` | `NULLABLE` | Metadatos estructurados saneados (jamás contraseñas, tokens, claves ni texto de recuerdos) |
| `created_at` | `UTCDateTime` | `NOT NULL, index` | Fecha y hora exacta en UTC |
