# Feature Specification: Plataforma legado-ia (Acceso, Conocimiento, Conversación y Continuidad Póstuma)

**Feature Branch**: `001-role-based-access`

**Created**: 2026-11-16

**Status**: Draft

**Input**: User description: "Sistema de acceso con dos roles, ENTRENADOR y AMIGO (más ALBACEA para continuidad póstuma), login en 2 pasos (Argon2id + ALTCHA + OTP email 6 dígitos o Passkey WebAuthn), invitaciones de un solo uso, códigos de recuperación, base de conocimiento cifrada con voz (faster-whisper) y modo entrevista, conversación de amigos con simulación LLM en streaming SSE + búsqueda web etiquetada '[Información externa]', y protocolo de modo póstumo con herramientas CLI de exportación, backup y migración SQLite/MariaDB."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Autenticación en Dos Pasos con Captcha ALTCHA, OTP por Email y Bloqueo Progresivo (Priority: P1)

Tanto el `ENTRENADOR` como el `AMIGO` (y el `ALBACEA`) inician sesión en dos pasos: (1) usuario, contraseña y desafío ALTCHA validado en servidor con protección contra repetición; (2) código numérico de 6 dígitos enviado por correo electrónico (caducidad 10 minutos, máximo 5 intentos, guardado como hash). La sesión solo se considera autenticada tras superar el paso 2 (mientras tanto permanece como sesión "pendiente de 2FA" con caducidad corta). Ante fallos repetidos se aplica bloqueo progresivo con backoff exponencial por usuario y por IP, y las respuestas de error e intervalos de tiempo son idénticos para usuario inexistente o contraseña incorrecta.

**Why this priority**: Es la barrera de seguridad primordial que protege el acceso a los recuerdos del entrenador y a las conversaciones privadas.

**Independent Test**: Se puede probar intentando iniciar sesión, verificando que la sesión tras el paso 1 no permite acceder a rutas protegidas (prevención de bypass de 2FA), comprobando la caducidad y límite de 5 intentos del OTP, la antirrepetición de ALTCHA y la igualdad de respuesta ante usuarios inexistentes.

**Acceptance Scenarios**:

1. **Given** un usuario activo en la pantalla de login, **When** envía usuario, contraseña válida y solución ALTCHA válida no reutilizada, **Then** el servidor crea una sesión "pendiente de 2FA" de corta duración, invalida cualquier OTP previo del usuario, genera un único código de 6 dígitos guardado como hash y lo envía por correo en texto plano.
2. **Given** una sesión "pendiente de 2FA", **When** el usuario intenta acceder directamente a cualquier ruta del entrenador o del amigo sin completar el paso 2, **Then** el servidor deniega el acceso y exige completar el segundo factor.
3. **Given** un código OTP emitido hace más de 10 minutos o con 5 intentos fallidos acumulados, **When** el usuario intenta validarlo, **Then** el servidor rechaza el código, lo invalida y aplica las reglas de bloqueo progresivo.
4. **Given** un intento de login con un nombre de usuario que no existe, **When** se procesa la petición, **Then** el servidor ejecuta un cálculo de hash ficticio para igualar tiempos de respuesta y devuelve exactamente el mismo mensaje de error que ante una contraseña incorrecta.

---

### User Story 2 - Aislamiento Estricto por Rol, Invitaciones de Un Solo Uso y Códigos de Recuperación (Priority: P1)

El sistema carece de registro abierto. El `ENTRENADOR` genera enlaces de invitación con un token aleatorio de 256 bits (del cual solo se guarda su hash en la base de datos), con caducidad y de un solo uso. Al activarse una cuenta mediante invitación se generan códigos de recuperación de un solo uso (guardados como hash). Un `AMIGO` no puede acceder a ninguna ruta ni funcionalidad del `ENTRENADOR`. Al autenticar o cerrar sesión se regenera o invalida el identificador de sesión en servidor, y las sesiones caducan por inactividad.

**Why this priority**: Asegura el principio de mínimo privilegio, evita el alta de desconocidos y previene la fijación o secuestro de sesiones.

**Independent Test**: Se puede probar generando una invitación como `ENTRENADOR`, registrando un `AMIGO`, comprobando que el enlace no puede reutilizarse, verificando que el `AMIGO` recibe `403 Forbidden` en cualquier ruta `/trainer/*`, usando un código de recuperación una vez y comprobando que queda invalidado.

**Acceptance Scenarios**:

1. **Given** un enlace de invitación con token de 256 bits vigente y no consumido, **When** el invitado completa su registro superando el desafío ALTCHA, **Then** se crea su cuenta con rol `AMIGO`, se genera su clave de datos (DEK) cifrada, se marca la invitación como usada y se le muestran por única vez sus códigos de recuperación de un solo uso.
2. **Given** un usuario autenticado con rol `AMIGO`, **When** intenta acceder a cualquier endpoint o vista del `ENTRENADOR`, **Then** la dependencia de autorización rechaza la petición y registra el intento en `audit_log`.
3. **Given** una sesión activa que supera el tiempo máximo de inactividad o cuyo usuario pulsa cerrar sesión, **When** se realiza una petición posterior con esa cookie, **Then** el servidor rechaza la sesión.

---

### User Story 3 - Segundo Factor y Gestión de Passkeys WebAuthn (Priority: P2)

Los usuarios pueden registrar credenciales WebAuthn (passkeys) desde su perfil y utilizarlas en el paso 2 del login como alternativa al código OTP por correo, exigiendo verificación de usuario (`userVerification=required`) y validando el contador de firmas (`sign_count`) para detectar credenciales clonadas. Desde su perfil pueden listar, renombrar y revocar passkeys, impidiendo revocar la última credencial sin confirmar con un código de recuperación.

**Why this priority**: Ofrece un segundo factor resistente al phishing y mantiene el acceso incluso si el servidor de correo externo presenta fallos.

**Independent Test**: Se puede probar con un autenticador virtual registrando una passkey, autenticándose en el paso 2 con ella, intentando reutilizar el mismo `challenge` (replay) y simulando un contador de firmas regresivo para verificar el bloqueo de la credencial.

**Acceptance Scenarios**:

1. **Given** un usuario en el paso 2 del login con al menos una passkey activa, **When** completa la ceremonia WebAuthn con `userVerification=required` y un contador de firmas válido, **Then** el challenge de sesión se consume inmediatamente y la sesión pasa a estado autenticado.
2. **Given** una respuesta de autenticación WebAuthn cuyo contador de firmas es menor o igual al registrado previamente (para autenticadores con contador > 0), **When** el servidor la verifica, **Then** rechaza el acceso, bloquea la credencial por sospecha de clonación y registra una alerta en `audit_log`.
3. **Given** un usuario en su perfil que intenta revocar su única passkey activa, **When** no proporciona un código de recuperación válido para confirmar la acción, **Then** el sistema impide la revocación.

---

### User Story 4 - Base de Conocimiento Cifrada, Grabación de Voz (`faster-whisper`) y Modo Entrevista (Priority: P2)

El `ENTRENADOR` construye su legado mediante entradas de texto, grabaciones de voz desde el navegador (`MediaRecorder`), un documento de personalidad versionado y un modo de entrevista guiada por temas (infancia, valores, trabajo, errores, consejos). Todo el contenido en base de datos y los archivos de audio en disco se cifran con la DEK del entrenador (AES-256-GCM) antes de guardarse. Los audios subidos se validan por contenido MIME real y tamaño, y se transcriben en segundo plano con `faster-whisper` generando un borrador editable por el entrenador antes de confirmar. El entrenador puede buscar en sus entradas (descifrado en memoria), borrar entradas junto con su audio de forma segura y exportar su base en streaming a formatos abiertos (`JSONL` y `TXT`).

**Why this priority**: Constituye el núcleo de conocimiento y personalidad que alimenta la simulación del entrenador.

**Independent Test**: Se puede probar creando entradas y subiendo un audio como `ENTRENADOR`, comprobando la transcripción editable, verificando en el archivo físico SQLite que el texto en claro no aparece en ningún byte, exportando a `JSONL`/`TXT` y comprobando que un `AMIGO` no tiene acceso a ninguna ruta de esta parte.

**Acceptance Scenarios**:

1. **Given** el `ENTRENADOR` en su panel, **When** guarda una entrada de recuerdo o una nueva versión del documento de personalidad, **Then** los datos se cifran en memoria con su DEK mediante AES-256-GCM antes de escribirse en la base de datos.
2. **Given** una grabación de voz subida por el `ENTRENADOR`, **When** supera la validación de tamaño y tipo MIME por contenido (*magic bytes*), **Then** el archivo se guarda cifrado en disco, se encola su transcripción con `faster-whisper` y el texto resultante queda disponible como borrador editable antes de su confirmación.
3. **Given** el `ENTRENADOR` solicitando exportar su base de conocimiento en `JSONL` o `TXT`, **When** se procesa la descarga, **Then** el sistema genera el archivo en streaming descifrando solo para el entrenador y registra la operación en `audit_log`.

---

### User Story 5 - Conversación de Amigos con la Simulación, Streaming SSE y Búsqueda Web Etiquetada (Priority: P2)

Cada `AMIGO` puede mantener conversaciones con la simulación del entrenador, cuyas respuestas se transmiten en tiempo real mediante SSE integrado con HTMX. El prompt combina el documento de personalidad activo, las entradas recuperadas mediante la interfaz `RetrievalStrategy` y el historial reciente, con instrucciones estrictas de hablar en primera persona sin inventar hechos biográficos ausentes. Si el modelo utiliza la herramienta de búsqueda web, el código del servidor envuelve los resultados con la etiqueta fija `[Información externa]` y muestra un indicador visible en la interfaz. Además, el código del servidor inyecta siempre el aviso de simulación en cada respuesta, sanea los datos para prevenir inyección de prompt, aplica límites diarios de tokens y cifra cada conversación con la DEK exclusiva del amigo.

**Why this priority**: Entrega el valor principal para los allegados (conversar con la simulación) garantizando privacidad entre amigos y transparencia ética.

**Independent Test**: Se puede probar con un servidor LLM simulado enviando mensajes como `AMIGO`, verificando la recepción por SSE, la presencia obligatoria del aviso de simulación añadido por código, el etiquetado `[Información externa]` cuando se invoca la búsqueda web y la imposibilidad de que un amigo lea conversaciones de otro amigo o la base de conocimiento cruda.

**Acceptance Scenarios**:

1. **Given** un `AMIGO` en una conversación activa, **When** envía un mensaje dentro de su cuota diaria de tokens, **Then** el mensaje y la respuesta generada en streaming SSE se almacenan cifrados con la DEK de ese amigo y la respuesta incluye siempre el aviso de simulación inyectado por el código.
2. **Given** una consulta que activa la herramienta de búsqueda web del LLM, **When** el servicio de búsqueda devuelve resultados, **Then** el código sanea y limita el texto, lo envuelve con `[Información externa]` antes de pasarlo al modelo y activa el indicador visual de fuente externa en el mensaje mostrado al usuario.
3. **Given** dos usuarios distintos con rol `AMIGO`, **When** uno intenta consultar o recibir el stream SSE de una conversación perteneciente al otro, **Then** el servidor deniega el acceso al filtrar por propietario y por aislamiento criptográfico de DEK.

---

### User Story 6 - Modo Póstumo con Albacea y Herramientas CLI de Portabilidad y Continuidad (Priority: P3)

El `ENTRENADOR` puede designar un albacea (`executor`). Cuando el albacea solicita activar el modo póstumo, se inicia un plazo de espera durante el cual se notifica al entrenador y a los contactos designados; si el entrenador no cancela la solicitud dentro del plazo, el albacea confirma el paso al estado `póstumo` (registrando cada paso en `audit_log`). En modo `póstumo`, la base de conocimiento queda en solo lectura estricto, el albacea puede gestionar invitaciones y accesos, y cada conversación muestra la indicación de que el entrenador ha fallecido. Asimismo, la CLI permite ejecutar `export-all`, `import-all` y `migrate-db` (de SQLite a MySQL/MariaDB verificando recuentos y checksums), además de copias de seguridad cifradas y un Documento de Continuidad (`README`).

**Why this priority**: Garantiza la preservación del legado tras el fallecimiento del entrenador y la supervivencia técnica a largo plazo sin bloqueo de proveedor ni de motor de base de datos.

**Independent Test**: Se puede probar simulando el flujo completo de solicitud póstuma (incluyendo intento de confirmación prematura antes del plazo y cancelación por el entrenador), verificando el bloqueo de escritura en modo `póstumo`, y ejecutando un test de ida y vuelta SQLite → MariaDB y restauración de copia cifrada sin pérdida de un solo registro.

**Acceptance Scenarios**:

1. **Given** el sistema en estado `activo`, **When** el albacea solicita activar el modo póstumo, **Then** el sistema pasa a `transicion_pendiente`, envía notificaciones al entrenador y contactos, registra el evento en `audit_log` e impide confirmar el estado `póstumo` hasta que venza el plazo de espera configurado.
2. **Given** el sistema en estado `póstumo`, **When** se intenta crear, editar o borrar cualquier entrada, audio o documento de personalidad, **Then** el servidor rechaza la operación por encontrarse la base de conocimiento en solo lectura, mientras muestra en todas las conversaciones la indicación de fallecimiento del entrenador.
3. **Given** una base de datos poblada en SQLite, **When** se ejecuta `migrate-db` hacia MariaDB o un ciclo `export-all` / `import-all`, **Then** todos los registros, textos cifrados y audios se transfieren íntegramente con verificación exacta de recuentos y checksums SHA-256.

---

### Edge Cases

- **Enumeración de usuarios en el login**: Usuario inexistente ejecuta verificación contra hash Argon2id ficticio y recibe mensaje idéntico al de contraseña incorrecta.
- **Intento de bypass de 2FA**: Una sesión con `is_2fa_verified=False` es rechazada en cualquier endpoint salvo los de verificación del paso 2.
- **Reutilización de soluciones ALTCHA o challenges WebAuthn**: El desafío se marca como consumido o se borra en el primer intento, rechazando cualquier repetición (*replay*).
- **Retroceso del contador de firmas WebAuthn**: Si un autenticador presenta un `sign_count` inferior o igual al almacenado, la credencial se revoca automáticamente y se audita como posible clonación.
- **Subida de archivo con extensión falsa**: Un ejecutable o script renombrado como `.webm` o `.wav` es rechazado al inspeccionar sus *magic bytes* en servidor.
- **Intento de inyección de prompt desde resultados web o recuerdos**: Los fragmentos se delimitan como datos no confiables, se sanean y el aviso de simulación se añade fuera del modelo en el código del servidor.
- **Abuso del procedimiento póstumo**: El albacea no puede saltarse el plazo de espera (`cooldown_hours`), y cualquier inicio de sesión o acción de cancelación del entrenador durante dicho plazo aborta inmediatamente la transición.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: El sistema DEBE validar toda su configuración al arrancar mediante `pydantic-settings` y abortar el inicio en producción si falta algún secreto obligatorio, si `APP_SECRET_KEY` es corta (< 32 bytes), si `APP_BASE_URL` no emplea `https://` o si la configuración de base de datos está incompleta.
- **FR-002**: Todo dato sensible en reposo (entradas, personalidad, archivos de audio en disco, conversaciones, mensajes y claves API) DEBE cifrarse con AES-256-GCM mediante cifrado por sobre (KEK externa a la BD + DEK por usuario), y las contraseñas DEBEN almacenarse con Argon2id.
- **FR-003**: El flujo de inicio de sesión DEBE realizarse en dos pasos obligatorios: (1) usuario, contraseña y captcha ALTCHA validado en servidor con HMAC y control de no reutilización; (2) código OTP de 6 dígitos enviado por correo (caducidad 10 min, máximo 5 intentos, un solo código activo por usuario, guardado como hash), Passkey WebAuthn (`userVerification=required`) o código de recuperación de un solo uso.
- **FR-004**: El sistema DEBE aplicar bloqueo progresivo con backoff exponencial por usuario y por IP ante fallos de autenticación, y DEBE evitar la enumeración de usuarios devolviendo errores idénticos y ejecutando un hash ficticio cuando el usuario no exista.
- **FR-005**: El alta de usuarios `AMIGO` (y `ALBACEA`) DEBE realizarse exclusivamente mediante invitación de un solo uso con token aleatorio de 256 bits (almacenado solo como hash) y fecha de caducidad, generando al activar la cuenta un lote de códigos de recuperación de un solo uso (almacenados como hash).
- **FR-006**: Las sesiones DEBEN almacenarse en servidor con ID aleatorio de 256 bits en cookies `HttpOnly; Secure; SameSite=Strict`, regenerando el ID al autenticar y al cerrar sesión, aplicando caducidad por inactividad y exigiendo validación CSRF en toda petición que modifique estado (incluyendo cabecera en peticiones HTMX).
- **FR-007**: El servidor DEBE enviar en todas las respuestas las cabeceras `Content-Security-Policy` con `'self'` (sin `'unsafe-inline'`, sin CDN ni scripts externos), `Strict-Transport-Security`, `X-Content-Type-Options=nosniff`, `X-Frame-Options=DENY`, `Referrer-Policy=no-referrer` y `Permissions-Policy` (micrófono solo en `'self'`).
- **FR-008**: El sistema DEBE permitir a los usuarios registrar, listar, renombrar y revocar credenciales WebAuthn (`py_webauthn`), verificando el contador de firmas contra clonación e impidiendo revocar la última credencial sin confirmar con un código de recuperación.
- **FR-009**: El `ENTRENADOR` DEBE disponer de un módulo de base de conocimiento con entradas cifradas, documento de personalidad versionado, modo entrevista guiada por temas, grabación y subida de audio validada por contenido MIME y tamaño, transcripción asíncrona con `faster-whisper` editable antes de confirmar, borrado seguro (entrada + archivo de audio) y exportación en streaming a `JSONL` y `TXT`.
- **FR-010**: Los usuarios con rol `AMIGO` DEBEN poder conversar en streaming SSE con la simulación del entrenador (construida con personalidad + estrategia `RetrievalStrategy` + historial), sin poder acceder jamás a las rutas del entrenador, a la base de conocimiento cruda ni a las conversaciones de otros amigos.
- **FR-011**: Cuando el modelo utilice la herramienta de búsqueda web, el código del servidor DEBE sanear y limitar los resultados, envolverlos con la etiqueta fija `[Información externa]` y mostrar un indicador visible en la interfaz; asimismo, el código del servidor DEBE añadir el aviso de simulación en cada respuesta.
- **FR-012**: El sistema DEBE soportar un protocolo auditado de transición a estado `póstumo` iniciado por el albacea designado, sujeto a un plazo de espera y notificación al entrenador y contactos; una vez confirmado el estado `póstumo`, la base de conocimiento DEBE quedar en solo lectura, el albacea DEBE poder gestionar invitaciones/accesos y las conversaciones DEBEN indicar que el entrenador ha fallecido.
- **FR-013**: La aplicación y sus migraciones Alembic (`render_as_batch=True`) DEBEN funcionar sin cambios en SQLite (con `foreign_keys=ON` y `WAL`) y en MySQL/MariaDB (`utf8mb4`, TLS para hosts remotos), e incluir comandos CLI (`export-all`, `import-all`, `migrate-db`) verificados mediante recuentos y checksums SHA-256.
- **FR-014**: El sistema DEBE registrar en `audit_log` todos los eventos de seguridad, exportaciones y pasos de sucesión sin incluir jamás contraseñas, códigos, tokens, claves ni el texto de recuerdos o conversaciones en los logs.

### Key Entities *(include if feature involves data)*

- **Usuario y Clave (`User`, `UserKey`)**: Cuenta con rol (`entrenador`, `amigo`, `albacea`), hash Argon2id, estado de bloqueo y su DEK cifrada con la KEK externa.
- **Sesión, OTP, Invitación y Recuperación (`Session`, `OTPCode`, `Invitation`, `RecoveryCode`)**: Entidades de control de acceso con estado `is_2fa_verified`, tokens hasheados, caducidad y consumo de un solo uso.
- **Credencial WebAuthn (`WebAuthnCredential`)**: Clave pública COSE, `credential_id`, `sign_count`, nombre de dispositivo y fechas de uso.
- **Conocimiento del Entrenador (`Entry`, `AudioFile`, `PersonalityDoc`, `InterviewTopic`)**: Entradas de recuerdos cifradas, archivos de voz cifrados en disco y transcritos con `faster-whisper`, versiones del documento de personalidad y temas de entrevista.
- **Conversación y Configuración LLM (`Conversation`, `Message`, `LLMSettings`)**: Hilos y mensajes cifrados con la DEK del amigo, indicadores de búsqueda externa y configuración de proveedor LLM con clave API cifrada.
- **Sucesión y Auditoría (`SystemState`, `Executor`, `SuccessionEvent`, `AuditLog`)**: Estado operativo (`activo`, `transicion_pendiente`, `postumo`), albaceas designados, eventos de transición y registro inmutable de auditoría.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: El 100 % de los intentos de acceso de un `AMIGO` a rutas del `ENTRENADOR` o de una sesión en paso 1 (`is_2fa_verified=False`) a rutas autenticadas son rechazados por el servidor y registrados en auditoría.
- **SC-002**: El 100 % de los textos sensibles (entradas, personalidad, mensajes, claves API y audios) se almacenan cifrados con AES-256-GCM; una búsqueda binaria del texto en claro sobre el archivo de base de datos SQLite o el directorio de audio arroja 0 coincidencias.
- **SC-003**: El 100 % de las respuestas de la simulación incluyen el aviso de simulación inyectado por el código del servidor, y el 100 % de las respuestas que emplean búsqueda web etiquetan los datos con `[Información externa]` y muestran el indicador visual al usuario.
- **SC-004**: La suite completa de pruebas automatizadas supera el 80 % de cobertura en los módulos de seguridad y pasa al 100 % tanto en SQLite como en MySQL/MariaDB.
- **SC-005**: La migración CLI (`migrate-db`) entre SQLite y MariaDB y el ciclo `export-all` / `import-all` transfieren el 100 % de los registros verificados mediante recuentos y checksums SHA-256 sin pérdida de integridad.
- **SC-006**: En modo `póstumo`, el 100 % de los intentos de modificación o borrado sobre la base de conocimiento son rechazados, garantizando la inmutabilidad del legado del entrenador.

## Assumptions

- **Provisión inicial del ENTRENADOR**: Se realiza mediante el comando CLI `init-trainer` en el despliegue inicial.
- **Plazo de espera para modo póstumo**: El periodo de seguridad entre la solicitud del albacea y la confirmación definitiva tiene un valor por defecto configurable de 72 horas, durante el cual el entrenador recibe avisos por email y puede cancelar la transición con un clic.
- **Caducidades por defecto**: Invitaciones (72 h), código OTP por email (10 min, máx. 5 intentos), sesión pendiente de 2FA (10 min), inactividad de sesión autenticada (30 min).
