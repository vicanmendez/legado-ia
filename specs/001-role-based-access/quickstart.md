# Quickstart & Validation Guide (`legado-ia`)

**Feature**: `001-role-based-access` (Guía de validación extremo a extremo Partes 1–6)
**Date**: 2026-11-16

---

## 1. Prerrequisitos

- Python 3.12+ y gestor `uv` instalado.
- Docker y Docker Compose (para validación con MariaDB y Ollama opcionales).

---

## 2. Configuración del Entorno (`.env`)

1. Copiar la plantilla versionada:
   ```bash
   cp .env.example .env
   ```
2. Generar una clave maestra (KEK) de 32 bytes en base64 para desarrollo o montarla en archivo:
   ```bash
   python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())" > .kek.secret
   chmod 600 .kek.secret
   ```
3. Configurar en `.env` las variables mínimas (`APP_ENV=development`, `APP_SECRET_KEY`, `ENCRYPTION_KEK_FILE=.kek.secret`, `ALTCHA_HMAC_KEY`, `DB_ENGINE=sqlite`, `DB_SQLITE_PATH=./legado.db`).

---

## 3. Instalación de Dependencias y Migraciones

```bash
# Instalar dependencias con lockfile estricto
uv sync --frozen

# Aplicar migraciones Alembic (render_as_batch=True)
uv run alembic upgrade head

# Inicializar la cuenta del ENTRENADOR
uv run python -m app.cli init-trainer --username entrenador --email entrenador@example.local
```

---

## 4. Ejecución de la Suite de Pruebas y Puertas de Calidad

### 4.1. Linting, Tipos y Auditoría Estática de Seguridad
```bash
uv run ruff check app tests migrations
uv run mypy app
uv run bandit -r app
uv run pip-audit
```

### 4.2. Pruebas Automatizadas en SQLite y MariaDB
```bash
# Ejecutar toda la suite sobre SQLite con verificación de cobertura >= 80% en seguridad
uv run pytest --cov=app/services --cov=app/routers --cov-fail-under=80

# Ejecutar la misma suite contra contenedor MariaDB (utf8mb4)
TEST_DB_ENGINE=mysql uv run pytest
```

---

## 5. Escenarios de Validación Extremo a Extremo

1. **Arranque Fail-Fast de Producción (Parte 1)**:
   - Ejecutar con `APP_ENV=production` y `APP_BASE_URL=http://localhost:8000` (sin HTTPS) o sin `ENCRYPTION_KEK_FILE`.
   - **Resultado esperado**: El proceso termina inmediatamente con error de validación de `pydantic-settings` antes de abrir el puerto HTTP.
2. **Login de Dos Factores, ALTCHA y Aislamiento de Roles (Parte 2)**:
   - Iniciar sesión como `entrenador` resolviendo el desafío ALTCHA y validando el código OTP de 6 dígitos enviado por correo (o usando uno de los códigos de recuperación impresos por `init-trainer`).
   - Intentar acceder a `/trainer/entries` con una sesión que solo completó el Paso 1 (`is_2fa_verified=False`). **Resultado esperado**: `401/403` (redirección al paso 2).
   - Generar una invitación desde `/trainer/invitations`, abrir el enlace de un solo uso en otra sesión, registrar un usuario `amigo` y verificar que al reutilizar el enlace se rechaza.
   - Con la sesión del `amigo`, intentar acceder a cualquier ruta `/trainer/*`. **Resultado esperado**: `403 Forbidden` y registro `ROLE_DENIED` en `audit_log`.
3. **Passkeys WebAuthn (Parte 3)**:
   - Registrar una passkey en `/profile/security` y verificar el inicio de sesión en el Paso 2 sin necesidad de código por email.
4. **Base de Conocimiento y Verificación de Cifrado en Disco (Parte 4)**:
   - Crear una entrada con un texto único (ej. `"RecuerdoSecreto1984"`) y subir un audio.
   - Inspeccionar directamente el archivo `legado.db` buscando la cadena `"RecuerdoSecreto1984"`. **Resultado esperado**: 0 coincidencias en el fichero binario SQLite.
5. **Conversación del Amigo y Etiquetado de Transparencia (Parte 5)**:
   - Iniciar una conversación como `amigo` en `/friend/conversations`.
   - Comprobar que toda respuesta incluye el aviso de simulación inyectado por el servidor y que cualquier resultado de búsqueda web aparece etiquetado con `[Información externa]`.
6. **Modo Póstumo y Migración SQLite → MariaDB (Parte 6)**:
   - Ejecutar `uv run python -m app.cli migrate-db --source-sqlite ./legado.db --target-from-env` hacia MariaDB y verificar que el comando confirma coincidencia del 100 % en recuentos y checksums SHA-256.
   - Ejecutar `export-all` e `import-all` verificando la restauración íntegra del paquete cifrado.
