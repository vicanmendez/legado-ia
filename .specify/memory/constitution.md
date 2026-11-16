<!--
Sync Impact Report
- Version change: N/A (template) -> 1.0.0
- Modified principles:
  - [PRINCIPLE_1_NAME] -> I. Seguridad por Diseño
  - [PRINCIPLE_2_NAME] -> II. Cifrado en Reposo
  - [PRINCIPLE_3_NAME] -> III. Autenticación Fuerte
  - [PRINCIPLE_4_NAME] -> IV. Auditoría
  - [PRINCIPLE_5_NAME] -> V. Mínima Dependencia de Terceros
- Added principles:
  - VI. Configuración por .env
  - VII. Portabilidad de Base de Datos
  - VIII. Portabilidad de Datos
  - IX. Transparencia
  - X. Pruebas Obligatorias (INNEGOCIABLE)
  - XI. Incrementalidad
- Added sections:
  - Propósito del Sistema y Restricciones Arquitectónicas
  - Flujo de Desarrollo y Puertas de Calidad
- Removed sections: None
- Templates requiring updates: None (resolved dynamically at runtime)
- Follow-up TODOs: None
-->
# legado-ia Constitution

## Core Principles

### I. Seguridad por Diseño
El sistema DEBE aplicar el principio de mínimo privilegio y denegar el acceso por defecto en todas las rutas, servicios y recursos. Toda entrada procedente del cliente o de fuentes externas DEBE validarse estrictamente en el servidor. Queda PROHIBIDO almacenar secretos en el repositorio de código o exponerlos en los registros (logs) de la aplicación.

*Racional*: Al custodiar recuerdos, rasgos de personalidad y conversaciones privadas de una persona y sus allegados, cualquier brecha compromete información íntima e irrecuperable.

### II. Cifrado en Reposo
Todo dato sensible en reposo DEBE cifrarse mediante AES-256-GCM utilizando cifrado por sobre (*envelope encryption*), compuesto por una clave maestra (KEK) almacenada fuera de la base de datos y una clave de datos (DEK) única por usuario. Las claves de API almacenadas en la base de datos DEBEN guardarse siempre cifradas. Las contraseñas DEBEN procesarse exclusivamente con Argon2id. Ningún dato sensible DEBE persistirse en texto claro.

*Racional*: El cifrado por sobre garantiza que una exposición de la base de datos no comprometa el contenido personal del entrenador, las conversaciones de los amigos ni las credenciales de terceros.

### III. Autenticación Fuerte
El sistema DEBE exigir usuario, contraseña, verificación de captcha y un segundo factor de autenticación (código enviado por correo electrónico o passkey mediante WebAuthn). El sistema NO DEBE permitir el registro abierto; el alta de usuarios DEBE realizarse exclusivamente por invitación. El sistema DEBE proporcionar códigos de recuperación de un solo uso para el restablecimiento de acceso.

*Racional*: Proteger el acceso a la simulación del entrenador frente a accesos no autorizados, ataques de fuerza bruta y enumeración automatizada de cuentas.

### IV. Auditoría
El sistema DEBE registrar todos los eventos relevantes de seguridad (inicios de sesión exitosos y fallidos, cambios de privilegios, uso de invitaciones, rotación de claves y exportaciones de datos). Los registros de auditoría JAMÁS DEBEN incluir contraseñas, claves criptográficas, tokens ni contenido sensible en claro.

*Racional*: Asegurar la trazabilidad ante incidentes de seguridad sin convertir los registros de auditoría en un vector de fuga de información confidencial.

### V. Mínima Dependencia de Terceros
Todo componente externo (proveedor de correo electrónico, proveedor de LLM, servicio de captcha) DEBE abstraerse tras interfaces internas y ser sustituible únicamente mediante configuración. La interfaz web NO DEBE cargar scripts externos ni recursos desde CDN de terceros; el servidor DEBE aplicar una política `Content-Security-Policy` (CSP) estricta limitada a `'self'`.

*Racional*: Garantizar la longevidad del sistema a largo plazo (incluso tras el fallecimiento del entrenador) evitando que el cierre o cambio de un proveedor externo inutilice la plataforma o introduzca vectores XSS.

### VI. Configuración por .env
Toda la configuración del entorno DEBE validarse al arrancar la aplicación utilizando `pydantic-settings`. Si falta algún secreto obligatorio o parámetro crítico en el entorno de producción, la aplicación DEBE abortar su inicio de forma inmediata (*fail-fast*). El repositorio DEBE mantener un archivo `.env.example` versionado y documentado; el archivo `.env` real JAMÁS DEBE incorporarse al control de versiones.

*Racional*: Prevenir despliegues inseguros con valores por defecto débiles y evitar errores de configuración silenciosos en tiempo de ejecución.

### VII. Portabilidad de Base de Datos
El mismo código de aplicación y de acceso a datos DEBE funcionar sin modificaciones tanto en SQLite como en MySQL/MariaDB. Toda interacción con la base de datos DEBE realizarse mediante SQLAlchemy sin emplear SQL específico de un motor concreto. Las fechas y horas DEBEN almacenarse en UTC, la codificación de texto DEBE ser `utf8mb4`, y las migraciones con Alembic DEBEN ejecutarse con `render_as_batch=True`. El flujo de integración continua (CI) DEBE ejecutar la suite completa de pruebas en ambos motores.

*Racional*: Permitir despliegues locales o ligeros sobre SQLite y despliegues en servidor sobre MySQL/MariaDB sin bifurcaciones de código ni bloqueos de migración.

### VIII. Portabilidad de Datos
La base de conocimiento del entrenador DEBE poder exportarse íntegramente en formatos abiertos estándar (`JSONL` y `TXT`). El proveedor de modelos de lenguaje (LLM) DEBE ser intercambiable a través de un cliente compatible con la API de OpenAI, utilizando Ollama por defecto para ejecución local y permitiendo OpenRouter de manera opcional.

*Racional*: Asegurar que el legado digital pertenezca a sus custodios y pueda preservarse o migrarse en el futuro con independencia de tecnologías propietarias.

### IX. Transparencia
El sistema DEBE declararse explícita y permanentemente ante el usuario como una simulación basada en inteligencia artificial. Todo contenido generado o enriquecido mediante búsqueda web DEBE etiquetarse de forma clara y visible como información externa ajena a la base de conocimiento original del entrenador.

*Racional*: Preservar la ética del sistema, evitar el engaño emocional a los allegados y distinguir con precisión entre el conocimiento real aportado por el entrenador y los datos externos.

### X. Pruebas Obligatorias (INNEGOCIABLE)
Toda funcionalidad relacionada con autenticación, autorización basada en roles, cifrado en reposo/sobre y compatibilidad entre motores de base de datos DEBE contar con pruebas automatizadas exhaustivas. Ninguna tarea, historia de usuario o incremento se dará por terminado mientras no existan pruebas que la cubran y toda la suite de tests esté en verde.

*Racional*: Los fallos en seguridad, control de acceso o criptografía pueden exponer datos irreversibles; la verificación automatizada en ambos motores es la única garantía objetiva de cumplimiento.

### XI. Incrementalidad
El desarrollo DEBE estructurarse en incrementos donde cada parte entregada sea completamente funcional, verificable y desplegable por sí sola sin depender de módulos futuros incompletos.

*Racional*: Reducir el riesgo de integración, facilitar la validación temprana de cada capa de seguridad y mantener el sistema siempre en un estado estable de producción.

## Propósito del Sistema y Restricciones Arquitectónicas

`legado-ia` es una aplicación web diseñada para replicar la personalidad, el lenguaje y el conocimiento de una persona (el «entrenador») con el fin de que sus allegados («amigos») puedan conversar con dicha simulación, incluso tras su fallecimiento.

- **Roles estrictos**: Separación clara de permisos entre el rol de «entrenador» (creación, curación y gestión de la base de conocimiento e invitaciones) y el rol de «amigo» (interacción conversacional autorizada con la simulación).
- **Aislamiento criptográfico**: La clave maestra (KEK) reside exclusivamente en la configuración de entorno validada por `pydantic-settings`; las claves por usuario (DEK) y las claves de API se almacenan cifradas con AES-256-GCM en la base de datos.
- **Autosuficiencia en cliente**: Todos los activos estáticos (HTML, CSS, JS, fuentes, iconos) se sirven localmente desde la propia aplicación bajo CSP `'self'`.

## Flujo de Desarrollo y Puertas de Calidad

1. **Verificación de Configuración**: Ningún cambio que añada variables de entorno puede fusionarse sin su correspondiente entrada en `.env.example` y su validación tipada en `pydantic-settings`.
2. **Puerta de Base de Datos Dual**: Toda migración de Alembic debe emplear `render_as_batch=True` y superar las pruebas automatizadas tanto en SQLite como en MySQL/MariaDB (`utf8mb4`, UTC).
3. **Puerta de Seguridad y Pruebas**: Ningún incremento se considera completado sin pruebas automatizadas en verde que validen autenticación, autorización por rol, cifrado y portabilidad de base de datos.
4. **Entregas Desplegables**: Cada fase o historia de usuario debe dejar la aplicación en un estado funcional y desplegable de forma autónoma.

## Governance

Esta Constitución prevalece sobre cualquier otra práctica, guía o decisión técnica del proyecto `legado-ia`.

- **Procedimiento de Enmienda**: Cualquier modificación a estos principios requiere documentar la justificación técnica o ética, actualizar este archivo y verificar el impacto en las especificaciones, planes y pruebas existentes.
- **Política de Versionado**: La versión de la Constitución sigue versionado semántico (`MAJOR.MINOR.PATCH`):
  - `MAJOR`: Eliminación o redefinición incompatible de principios existentes o reducción de garantías de seguridad.
  - `MINOR`: Adición de un nuevo principio o expansión sustancial de las reglas de gobernanza.
  - `PATCH`: Aclaraciones de redacción, correcciones tipográficas o refinamientos sin cambios semánticos.
- **Revisión de Cumplimiento**: Toda especificación (`/speckit-specify`), plan técnico (`/speckit-plan`), lista de tareas (`/speckit-tasks`) e implementación (`/speckit-implement`) DEBE verificar explícitamente el cumplimiento de los 11 principios aquí definidos.

**Version**: 1.0.0 | **Ratified**: 2026-11-16 | **Last Amended**: 2026-11-16
