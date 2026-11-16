# legado-ia — Documento de Continuidad y Guía de Operación

`legado-ia` es una aplicación web autoalojada diseñada para preservar y replicar la personalidad, el lenguaje y la base de conocimiento de una persona (el **entrenador**) para que sus allegados (**amigos**) conversen con dicha simulación, incluso tras su fallecimiento (**modo póstumo** gestionado por un **albacea**).

---

## 1. Principios de Seguridad y Criptografía

- **Cifrado por Sobre (Envelope Encryption) AES-256-GCM**:
  - La **KEK** (*Key Encryption Key*, 32 bytes en base64) reside exclusivamente fuera de la base de datos (en el archivo apuntado por `ENCRYPTION_KEK_FILE` o secreto de Docker `/run/secrets/encryption_kek`).
  - Cada usuario posee su propia **DEK** (*Data Encryption Key*) de 256 bits cifrada con la KEK en `user_keys`.
  - Los recuerdos (`entries`), el documento de personalidad (`personality_doc`) y los archivos de voz en disco (`audio_files`) están cifrados con la DEK del entrenador.
  - Las conversaciones (`conversations`) y mensajes (`messages`) de cada amigo están cifrados con la DEK exclusiva de ese amigo.
- **Contraseñas y Códigos**:
  - Contraseñas procesadas con **Argon2id**.
  - Códigos OTP de 6 dígitos (caducidad 10 min, máximo 5 intentos), tokens de invitación de 256 bits y códigos de recuperación de un solo uso guardados únicamente como hashes irreversibles.

---

## 2. Procedimiento de Continuidad para el Albacea / Custodio

### 2.1. Custodia y Recuperación de la KEK
Para que el sistema pueda descifrar la base de conocimiento o restaurarse en otro servidor, **es imprescindible conservar**:
1. El archivo de clave maestra (`ENCRYPTION_KEK_FILE`, 32 bytes codificados en base64), **o bien**
2. Un paquete de respaldo generado con `export-all` junto con su **frase de paso** (*passphrase*), el cual es autónomo y permite restaurar todo el legado en una instancia nueva con una KEK diferente.

### 2.2. Restauración desde Copia de Seguridad Cifrada (`export-all` / `import-all`)
```bash
# 1. Generar un paquete cifrado autónomo (JSONL + TXT + Audios + Manifiesto SHA-256)
uv run python -m app.cli export-all --output ./backup-legado.enc --passphrase "frase-segura-de-custodia"

# 2. En un servidor nuevo, inicializar el esquema y el entrenador custodio
uv run python -m app.cli init-trainer --username entrenador --email custodio@ejemplo.local

# 3. Restaurar el paquete (verifica etiqueta AES-256-GCM y todos los hashes SHA-256 antes de escribir)
uv run python -m app.cli import-all --input ./backup-legado.enc --passphrase "frase-segura-de-custodia"
```

### 2.3. Migración entre SQLite y MySQL/MariaDB (`migrate-db`)
El mismo código funciona sin cambios en SQLite y en MySQL/MariaDB (`utf8mb4`, UTC). Para migrar de un archivo SQLite local a un servidor MariaDB verificando el 100 % de los recuentos y checksums SHA-256:
```bash
DB_ENGINE=mysql DB_HOST=127.0.0.1 DB_NAME=legado_ia DB_USER=legado DB_PASSWORD=secreto \
  uv run python -m app.cli migrate-db --source-sqlite ./legado.db --target-from-env
```

### 2.4. Cambio de Proveedor de LLM, Correo o Búsqueda Web
Ningún proveedor externo está acoplado al código:
- **LLM (compatible con OpenAI)**: Por defecto utiliza **Ollama** local (`LLM_BASE_URL=http://localhost:11434/v1`). Para cambiar a **OpenRouter** u otro servidor compatible, basta con actualizar `LLM_BASE_URL`, `LLM_MODEL` y `LLM_API_KEY` en `.env` o desde `/trainer/llm-settings`.
- **Correo SMTP**: Configurable en `.env` mediante `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_STARTTLS` y `MAIL_FROM`.
- **Búsqueda Web**: Configurable desde los ajustes del entrenador (`web_search_url`, ej. instancia SearXNG local). Todos los resultados externos son etiquetados por código con `[Información externa]`.

### 2.5. Activación del Modo Póstumo
1. El albacea accede a `/executor/panel` y solicita la transición (`POST /executor/request-transition`).
2. Se abre el plazo de espera (`cooldown_hours`, por defecto 72 h) y el sistema envía avisos urgentes al correo del entrenador y a los contactos designados.
3. Si el entrenador inicia sesión o cancela la solicitud durante ese plazo, la transición se aborta inmediatamente.
4. Cumplido el plazo sin cancelación, el albacea confirma la activación (`POST /executor/confirm-posthumous`). A partir de ese instante:
   - La base de conocimiento queda bloqueada en **solo lectura** de forma permanente.
   - El albacea puede emitir invitaciones para allegados.
   - Todas las conversaciones incluyen la indicación expresa de que el entrenador ha fallecido.
