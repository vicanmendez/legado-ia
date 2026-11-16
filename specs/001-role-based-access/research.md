# Phase 0 Research: Decisiones Técnicas y Patrones de Arquitectura (`legado-ia`)

**Feature**: `001-role-based-access` (Plan maestro incremental Partes 1–6)
**Date**: 2026-11-16

---

## 1. Cifrado por Sobre (Envelope Encryption) con AES-256-GCM y Gestión de Claves

- **Decision**: Implementar cifrado por sobre en dos niveles utilizando `cryptography.hazmat.primitives.ciphers.aead.AESGCM`:
  1. **KEK (Key Encryption Key)**: Clave maestra de 256 bits leída al arrancar desde el archivo indicado por `ENCRYPTION_KEK_FILE` (Docker secret en producción) o `ENCRYPTION_KEK` (codificada en base64, permitida únicamente cuando `APP_ENV != "production"`). Nunca se almacena en la base de datos.
  2. **DEK (Data Encryption Key) por usuario**: Al crear un usuario (`ENTRENADOR` o `AMIGO`), se genera una clave aleatoria de 256 bits (`secrets.token_bytes(32)`). La DEK se cifra con la KEK mediante AES-256-GCM y se persiste en `user_keys`.
  3. **Formato de blob cifrado**: `version (1 byte = 0x01) || nonce (12 bytes) || ciphertext || tag (16 bytes)`, almacenado en columnas `LargeBinary` (con variante `LONGBLOB` en MySQL/MariaDB) o en archivos binarios en disco para el audio.
  4. **Autenticación de contexto (AAD)**: Cada operación AES-256-GCM incluye como *Associated Authenticated Data* (`aad`) el nombre de la entidad, el identificador del registro o propietario (`f"{table}:{owner_id}"`) para impedir ataques de intercambio de textos cifrados (*ciphertext swapping*) entre columnas o usuarios.
- **Rationale**: Si un atacante obtiene un volcado completo de la base de datos SQLite o MariaDB, carece de la KEK (alojada en memoria/secretos del contenedor) y no puede descifrar las DEK ni los recuerdos o conversaciones. Además, si es necesario rotar la KEK en el futuro, basta con re-cifrar las filas de `user_keys` sin tocar los gigabytes de entradas, mensajes ni audios.
- **Alternatives considered**:
  - *Cifrado a nivel de disco (LUKS) o TDE del motor de BD*: Rechazado porque deja los datos en claro para cualquier consulta a la base de datos o volcado lógico, incumpliendo el Principio II (verificación de ausencia de texto en claro dentro del archivo `.sqlite`).
  - *Derivar la DEK directamente de la contraseña del usuario*: Rechazado como mecanismo único porque en un sistema póstumo la simulación debe poder leer la base de conocimiento del entrenador sin que el entrenador inicie sesión interactivamente, y un cambio o recuperación de contraseña obligaría a migrar claves o perder datos si no existe custodia por KEK.

---

## 2. Compatibilidad Dual SQLite y MySQL/MariaDB con SQLAlchemy 2.x y Alembic

- **Decision**:
  - Usar exclusivamente SQLAlchemy 2.x con sintaxis tipada `Mapped[...]` y `mapped_column(...)`.
  - Definir longitudes explícitas en todas las cadenas (`String(n)`) para que MySQL/MariaDB permita indexarlas y aplicar restricciones `UNIQUE`.
  - Definir un tipo compuesto `EncryptedBlob = LargeBinary().with_variant(LONGBLOB(), "mysql", "mariadb")` para evitar el truncamiento de 64 KB del tipo `BLOB` estándar de MySQL.
  - Definir un `TypeDecorator` `UTCDateTime` que garantice que todo `datetime` leído o escrito tenga ` tzinfo=timezone.utc`, normalizando el comportamiento de SQLite (que almacena cadenas ISO) y MySQL/MariaDB (que almacena `DATETIME` sin zona implícita).
  - En SQLite, registrar un listener del evento `connect` del engine para ejecutar `PRAGMA foreign_keys=ON` y `PRAGMA journal_mode=WAL`.
  - En MySQL/MariaDB, construir la URL con `sqlalchemy.engine.URL.create(drivername="mysql+pymysql", ...)` pasando `charset="utf8mb4"` y configurando `connect_args={"ssl": {"ca": settings.DB_SSL_CA}}` cuando el host no sea `localhost`/`127.0.0.1`.
  - Configurar `render_as_batch=True` en `migrations/env.py` para que las operaciones `ALTER TABLE` de Alembic funcionen de forma idéntica en SQLite y MariaDB.
- **Rationale**: Garantiza portabilidad real sin condicionales repartidos por la lógica de negocio y permite ejecutar exactamente las mismas migraciones y tests en ambos motores.
- **Alternatives considered**:
  - *Mantener dos carpetas de migraciones separadas*: Rechazado por duplicación y riesgo de divergencia de esquema.

---

## 3. Autenticación en Dos Pasos, Anti-Enumeración, ALTCHA y WebAuthn

- **Decision**:
  - **Estado de sesión en servidor**: Al superar el Paso 1 (usuario + contraseña Argon2id + ALTCHA), se crea una fila en `sessions` con `is_2fa_verified = False` y una caducidad corta de 10 minutos. Ninguna ruta protegida por `require_user` acepta sesiones con `is_2fa_verified = False`; únicamente las rutas del Paso 2 (`/auth/2fa`, `/auth/webauthn/authenticate/*`, `/auth/recovery`) aceptan dicho estado intermedio. Al superar el Paso 2, se regenera el token de sesión de 256 bits (`secrets.token_urlsafe(32)`), se marca `is_2fa_verified = True` y se amplía la caducidad por inactividad.
  - **Anti-enumeración de usuarios**: Se precalcula al arrancar la aplicación un hash Argon2id ficticio (`DUMMY_PASSWORD_HASH`). Cuando el usuario no existe, el servidor ejecuta igualmente `PasswordHasher.verify(DUMMY_PASSWORD_HASH, password)` antes de devolver el mismo mensaje de error genérico que cuando la contraseña falla.
  - **ALTCHA autoalojado**: El servidor expone `GET /auth/altcha-challenge` firmando con `ALTCHA_HMAC_KEY` un desafío con caducidad de 5 minutos. Al verificar la solución, el hash del desafío resuelto se registra en una tabla/caché de desafíos consumidos hasta su expiración para impedir ataques de repetición (*replay*).
  - **WebAuthn (`py_webauthn`)**: En el registro y autenticación se genera un `challenge` criptográfico de 32 bytes guardado en la sesión en servidor y borrado inmediatamente en la primera tentativa de verificación (uso único). Se exige `user_verification="required"` y se comprueba estrictamente que `new_sign_count > stored_sign_count` (cuando el autenticador reporta `sign_count > 0`); si el contador retrocede o se repite, se bloquea la credencial y se registra una alerta en `audit_log`.
- **Rationale**: Elimina vectores clásicos de bypass de 2FA (manipulación de cookies de cliente), enumeración por canal lateral de tiempo, reutilización de captchas y clonación de passkeys.
- **Alternatives considered**:
  - *Sesiones firmadas en cookie (JWT / itsdangerous)*: Rechazado porque no permite revocación inmediata en servidor al cerrar sesión ni invalidación instantánea de desafíos de un solo uso.

---

## 4. Procesamiento Seguro de Audio y Transcripción en Segundo Plano (`faster-whisper`)

- **Decision**:
  - Validar los archivos subidos leyendo los primeros bytes (*magic bytes*: cabeceras WebM/Matroska `1A 45 DF A3`, Ogg `4F 67 67 53` o WAV `52 49 46 46`) además de imponer un tamaño máximo en streaming antes de volcar a memoria.
  - Cifrar el contenido de audio inmediatamente con la DEK del entrenador (AES-256-GCM) antes de escribirlo en el directorio de almacenamiento (`AUDIO_STORAGE_PATH`), usando como nombre de archivo un UUIDv4 sin conservar el nombre original del cliente.
  - Ejecutar la transcripción con `faster-whisper` en un trabajador en segundo plano que descifra el audio en un búfer en memoria (`io.BytesIO`, sin escribir nunca un archivo `.wav`/`.webm` temporal en claro en `/tmp`), cifra el borrador de transcripción resultante con la DEK del entrenador y marca la entrada como `pendiente_revision` para que el entrenador la edite y confirme.
- **Rationale**: Evita que queden fragmentos de voz en claro en `/tmp` o en el sistema de archivos si el proceso falla a mitad de la transcripción.
- **Alternatives considered**:
  - *Archivos temporales en `/tmp` para `faster-whisper`*: Rechazado porque `faster-whisper` acepta objetos tipo archivo (`BinaryIO`) en memoria, evitando cualquier escritura en claro en disco.

---

## 5. Arquitectura de Conversación LLM, Streaming SSE, Búsqueda Web y Defensa contra Prompt Injection

- **Decision**:
  - **Desacoplamiento de recuperación (`RetrievalStrategy`)**: Definir una interfaz (`Protocol`) `RetrievalStrategy.retrieve(trainer_id, query, limit) -> list[DecryptedEntry]`. En las Partes 4–5 se implementa `RecentAndRelevantEntriesStrategy` (descifrado en memoria de las entradas confirmadas del entrenador, priorizando coincidencias léxicas y las últimas $N$ entradas configurables). En el futuro puede reemplazarse por una estrategia de embeddings locales sin modificar el servicio de chat ni los routers.
  - **Defensa contra inyección de prompt y etiquetado determinista**:
    1. El prompt de sistema instruye al modelo a hablar en primera persona con el estilo del documento de personalidad del entrenador, prohibiendo inventar hechos biográficos ausentes y tratando el contexto recuperado y los resultados web como datos no confiables delimitados por etiquetas XML/estructuradas (`<recuerdo_entrenador>`, `<resultado_web>`).
    2. Cuando el modelo invoca la herramienta de búsqueda web, el código del servidor sanea el texto (elimina caracteres de control, trunca a longitud máxima por fragmento) y antepone de forma determinista el prefijo `"[Información externa] "` antes de inyectarlo en el contexto de herramienta, activando además el flag `used_web_search = True` en el mensaje guardado para mostrar la insignia visual en la interfaz.
    3. El aviso de simulación (`"Aviso: Estás conversando con una simulación digital..."`, más la nota de estado póstumo si el sistema está en modo `póstumo`) es añadido e inyectado por el servidor en la respuesta y en la plantilla HTML, nunca delegado a la voluntad del LLM.
  - **Aislamiento criptográfico entre entrenador y amigos**: Durante la generación del prompt, el servidor descifra en memoria el documento de personalidad y las entradas con la DEK del entrenador (desbloqueada mediante la KEK del servidor), pero la conversación y los mensajes resultantes se cifran con la DEK exclusiva del `AMIGO` propietario de la conversación.
- **Rationale**: Cumple los Principios II, V, VIII y IX, impidiendo que un amigo acceda a las conversaciones de otro amigo o a la base de conocimiento cruda, y garantizando que el etiquetado de transparencia sea ineludible.
- **Alternatives considered**:
  - *Confiar en que el LLM incluya el aviso de simulación por prompt*: Rechazado expresamente por la especificación y la Constitución (el modelo podría omitirlo por alucinación o inyección de prompt).

---

## 6. Protocolo de Sucesión (Modo Póstumo), Migración entre Motores y Continuidad

- **Decision**:
  - **Protocolo de activación póstuma**: El entrenador puede designar uno o más albaceas (`executors`) y configurar un plazo de espera de seguridad (`cooldown_hours`, por defecto 72 horas). Cuando el albacea solicita activar el modo póstumo:
    1. El estado pasa a `transicion_pendiente` y se registra en `succession_events` y `audit_log`.
    2. Se envía notificación inmediata por correo electrónico al entrenador y a los contactos registrados con un enlace de cancelación inmediata ("Estoy vivo / Cancelar transición").
    3. Si el entrenador inicia sesión o pulsa cancelar durante el plazo de espera, la transición se aborta y se registra el evento.
    4. Transcurrido el plazo sin cancelación, el albacea confirma la activación final pasando el sistema a estado `postumo`.
  - **Efectos del modo `postumo`**: Un dependencia transversal impide cualquier creación, edición o borrado sobre `entries`, `audio_files`, `personality_doc` e `interview_topics` (modo solo lectura estricto), habilita al albacea para gestionar invitaciones y revocar accesos de amigos, y añade el indicador de fallecimiento del entrenador en las conversaciones.
  - **CLI de continuidad (`migrate-db`, `export-all`, `import-all`)**:
    - `migrate-db`: Abre dos `Engine` de SQLAlchemy simultáneos (origen SQLite y destino MySQL/MariaDB), copia tabla por tabla en orden topológico dentro de una transacción, y verifica al finalizar que el recuento de filas y el hash SHA-256 acumulado de los campos clave coincidan al 100 %.
    - `export-all`: Genera un archivo empaquetado (`.tar` cifrado con AES-256-GCM derivado de una frase de paso mediante Argon2id) que contiene el manifiesto con checksums SHA-256, las entradas/personalidad en `JSONL` y `TXT`, y los archivos de audio.
- **Rationale**: Impide que un albacea malintencionado o una cuenta de albacea comprometida active el modo póstumo instantáneamente sin que el entrenador en vida pueda detenerlo, y asegura que el legado pueda trasladarse de un entorno doméstico (SQLite) a un servidor definitivo (MariaDB) sin pérdida de datos.
- **Alternatives considered**:
  - *Activación inmediata del modo póstumo en un solo clic*: Rechazado por el riesgo de activación accidental o abuso en vida del entrenador.
