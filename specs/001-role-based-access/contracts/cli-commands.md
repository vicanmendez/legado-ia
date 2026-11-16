# Interface Contracts: Comandos CLI de Administración y Continuidad (`app/cli.py`)

**Feature**: `001-role-based-access` (Contratos CLI Partes 1–6)
**Date**: 2026-11-16

---

## Invocación General

Todos los comandos se ejecutan mediante `uv run python -m app.cli <comando> [opciones]` y cargan la configuración validada por `pydantic-settings` desde `.env` y secretos montados.

---

## 1. `init-trainer`
Crea la cuenta inicial del `ENTRENADOR` (cuando no existe ningún entrenador en la base de datos), genera su DEK cifrada con la KEK, inicializa la fila singleton `system_state` y los temas iniciales de entrevista (`interview_topics`), e imprime por consola su lote de códigos de recuperación de un solo uso.

```bash
uv run python -m app.cli init-trainer --username <usuario> --email <correo>
```
- Solicita la contraseña de forma interactiva sin eco (`getpass`).
- Registra el evento `CLI_INIT_TRAINER` en `audit_log`.
- Devuelve código de salida `0` si se creó con éxito, `1` si ya existe un entrenador activo.

---

## 2. `export-all`
Exporta la totalidad del legado (entradas en `JSONL` y `TXT`, historial de documento de personalidad, archivos de audio descifrados y re-empaquetados, metadatos de configuración y `manifest.json` con hashes SHA-256) en un único paquete cifrado con AES-256-GCM usando una clave derivada con Argon2id a partir de una frase de paso.

```bash
uv run python -m app.cli export-all --output /ruta/legado-backup.enc
```
- Solicita frase de paso del paquete (o lee `BACKUP_PASSPHRASE_FILE` para copias programadas).
- Verifica cada hash SHA-256 al escribir el manifiesto.
- Registra `CLI_EXPORT_ALL` en `audit_log`.

---

## 3. `import-all`
Restaura un paquete generado por `export-all` en una instancia limpia, verificando primero la autenticidad del contenedor AES-256-GCM y todos los checksums SHA-256 del `manifest.json`, y re-cifrando los datos con la KEK/DEK de la instancia destino.

```bash
uv run python -m app.cli import-all --input /ruta/legado-backup.enc
```
- Si cualquier checksum SHA-256 falla o la etiqueta GCM es inválida, aborta la restauración mediante rollback completo sin dejar datos parciales.

---

## 4. `migrate-db`
Migra sin pérdida todos los registros desde una base de datos origen (por ejemplo SQLite local) hacia una base de datos destino (por ejemplo MySQL/MariaDB en servidor) utilizando exclusivamente SQLAlchemy.

```bash
uv run python -m app.cli migrate-db \
  --source-sqlite /ruta/origen.db \
  --target-from-env
```
- Ejecuta las migraciones de Alembic en el destino hasta la revisión `head`.
- Copia todas las tablas en orden topológico preservando claves primarias y foráneas.
- **Verificación obligatoria post-migración**: comprueba tabla por tabla que el recuento de filas (`COUNT(*)`) y el resumen criptográfico SHA-256 de todas las filas en el destino coincidan exactamente con el origen. Si hay cualquier discrepancia, hace rollback y devuelve código distinto de cero.
