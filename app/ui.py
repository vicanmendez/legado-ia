"""Renderizador HTML seguro (con escapado automático UTF-8 y estilos locales /static/css/main.css)."""

from __future__ import annotations

import html
from typing import Any

from app.routers.dependencies import HTTPRequestContext, HTTPResponseData


def wants_html(req: HTTPRequestContext) -> bool:
    """Detecta si la petición proviene de un navegador esperando HTML (vs cliente JSON/API)."""
    if req.json_data is not None:
        return False
    accept = req.headers.get("Accept", "") or req.headers.get("accept", "")
    if "text/html" in accept or req.form_data:
        return True
    return False


def html_response(content: str, status_code: int = 200) -> HTTPResponseData:
    """Devuelve una respuesta HTTP con Content-Type: text/html; charset=utf-8 garantizado."""
    return HTTPResponseData(
        status_code=status_code,
        body=content,
        headers={"Content-Type": "text/html; charset=utf-8"},
    )


def redirect_response(location: str) -> HTTPResponseData:
    """Redirección HTTP 303 See Other tras enviar un formulario en el navegador."""
    return HTTPResponseData(
        status_code=303,
        body="",
        headers={
            "Location": location,
            "Content-Type": "text/html; charset=utf-8",
        },
    )


def render_layout(
    title: str,
    body_html: str,
    csrf_token: str = "",
    role: str | None = None,
    posthumous_mode: bool = False,
    extra_scripts: list[str] | None = None,
) -> str:
    """Envuelve el contenido en la plantilla base con cabeceras, CSS local y banner de simulación."""
    esc_title = html.escape(title)
    esc_csrf = html.escape(csrf_token)

    nav_html = ""
    if role == "entrenador":
        nav_html = (
            '<div class="nav-links">'
            '<a href="/trainer/dashboard">Panel Entrenador</a>'
            '<form method="post" action="/auth/logout" style="display:inline;margin:0;">'
            f'<input type="hidden" name="_csrf_token" value="{esc_csrf}">'
            '<button type="submit" class="btn-secondary">Cerrar sesión</button>'
            "</form></div>"
        )
    elif role == "amigo":
        nav_html = (
            '<div class="nav-links">'
            '<a href="/friend/dashboard">Conversaciones</a>'
            '<form method="post" action="/auth/logout" style="display:inline;margin:0;">'
            f'<input type="hidden" name="_csrf_token" value="{esc_csrf}">'
            '<button type="submit" class="btn-secondary">Cerrar sesión</button>'
            "</form></div>"
        )
    elif role == "albacea":
        nav_html = (
            '<div class="nav-links">'
            '<a href="/executor/dashboard">Panel Albacea</a>'
            '<form method="post" action="/auth/logout" style="display:inline;margin:0;">'
            f'<input type="hidden" name="_csrf_token" value="{esc_csrf}">'
            '<button type="submit" class="btn-secondary">Cerrar sesión</button>'
            "</form></div>"
        )

    posthumous_banner = ""
    if posthumous_mode:
        posthumous_banner = (
            '<div class="banner-posthumous" role="alert">'
            "<strong>Modo Póstumo Activo:</strong> El entrenador ha fallecido. "
            "Su base de conocimiento permanece en modo de solo lectura para preservar su legado."
            "</div>"
        )

    scripts_tags = "\n".join(
        f'  <script src="{html.escape(src)}" defer></script>' for src in (extra_scripts or [])
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="{esc_csrf}">
  <title>{esc_title} - legado-ia</title>
  <link rel="stylesheet" href="/static/css/main.css">
  <script src="/static/vendor/htmx.min.js" defer></script>
  <script src="/static/js/csrf.js" defer></script>
{scripts_tags}
</head>
<body>
  <header>
    <div class="topbar">
      <a href="/" class="brand">legado-ia</a>
      {nav_html}
    </div>
    <div class="banner-simulation" role="status">
      <strong>Aviso de Transparencia:</strong> Este sistema es una simulación digital basada en inteligencia artificial. No estás interactuando con una persona en tiempo real.
    </div>
    {posthumous_banner}
  </header>
  <main id="main-content">
    {body_html}
  </main>
</body>
</html>"""


def render_login_page(csrf_token: str, error_msg: str | None = None) -> str:
    esc_csrf = html.escape(csrf_token)
    err_block = (
        f'<div class="alert-error">{html.escape(error_msg)}</div>' if error_msg else ""
    )
    body = f"""
    <div class="auth-container">
      <section class="card">
        <h1>Iniciar sesión</h1>
        <p class="muted">Paso 1 de 2: Introduce tus credenciales y espera la verificación local ALTCHA.</p>
        {err_block}
        <form method="post" action="/auth/login">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label for="username">Usuario</label>
            <input type="text" id="username" name="username" required maxlength="64" autocomplete="username">
          </div>
          <div class="form-group">
            <label for="password">Contraseña</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
          </div>
          <input type="hidden" name="altcha_payload" id="altcha_payload">
          <div class="altcha-box" id="altcha_status">
            Inicializando verificación antiautomatización ALTCHA...
          </div>
          <button type="submit" id="altcha_submit_btn" style="width:100%;">Continuar al segundo factor</button>
        </form>
      </section>
    </div>
    """
    return render_layout(
        "Iniciar sesión", body, csrf_token=csrf_token, extra_scripts=["/static/js/altcha.js"]
    )


def render_2fa_page(csrf_token: str, error_msg: str | None = None) -> str:
    esc_csrf = html.escape(csrf_token)
    err_block = (
        f'<div class="alert-error">{html.escape(error_msg)}</div>' if error_msg else ""
    )
    body = f"""
    <div class="auth-container">
      <section class="card">
        <h1>Verificación en dos pasos (2FA)</h1>
        <p class="muted">Hemos enviado un código de 6 dígitos a tu correo electrónico (válido por 10 minutos, máximo 5 intentos).</p>
        {err_block}
        <form method="post" action="/auth/2fa/otp" style="margin-bottom:1.5rem;">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label for="code">Código de 6 dígitos por email</label>
            <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{{6}}" placeholder="123456" required autocomplete="one-time-code">
          </div>
          <button type="submit" style="width:100%;">Verificar código OTP</button>
        </form>
        <hr style="border-color:var(--border);margin:1.25rem 0;">
        <h3>¿Sin acceso al correo?</h3>
        <p class="muted">Usa uno de tus códigos de recuperación de un solo uso generados al activar tu cuenta:</p>
        <form method="post" action="/auth/2fa/recovery">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label for="recovery_code">Código de recuperación</label>
            <input type="text" id="recovery_code" name="recovery_code" placeholder="XXXXX-XXXXX" required>
          </div>
          <button type="submit" class="btn-secondary" style="width:100%;">Entrar con código de recuperación</button>
        </form>
      </section>
    </div>
    """
    return render_layout(
        "Segundo Factor (2FA)",
        body,
        csrf_token=csrf_token,
        extra_scripts=["/static/js/webauthn.js"],
    )


def render_invite_register_page(
    csrf_token: str,
    token: str,
    target_role: str,
    error_msg: str | None = None,
) -> str:
    esc_csrf = html.escape(csrf_token)
    esc_token = html.escape(token)
    err_block = (
        f'<div class="alert-error">{html.escape(error_msg)}</div>' if error_msg else ""
    )
    body = f"""
    <div class="auth-container">
      <section class="card">
        <h1>Activar cuenta por invitación</h1>
        <p class="muted">Has sido invitado con el rol <code>{html.escape(target_role.upper())}</code>. Este enlace es de un solo uso.</p>
        {err_block}
        <form method="post" action="/auth/invite/{esc_token}">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label for="username">Nombre de usuario (3-64 caracteres)</label>
            <input type="text" id="username" name="username" required maxlength="64">
          </div>
          <div class="form-group">
            <label for="email">Correo electrónico</label>
            <input type="email" id="email" name="email" required maxlength="255">
          </div>
          <div class="form-group">
            <label for="password">Contraseña (mínimo 10 caracteres)</label>
            <input type="password" id="password" name="password" required minlength="10">
          </div>
          <input type="hidden" name="altcha_payload" id="altcha_payload">
          <div class="altcha-box" id="altcha_status">
            Verificando desafío ALTCHA...
          </div>
          <button type="submit" id="altcha_submit_btn" style="width:100%;">Activar cuenta y generar códigos</button>
        </form>
      </section>
    </div>
    """
    return render_layout(
        "Registro por Invitación",
        body,
        csrf_token=csrf_token,
        extra_scripts=["/static/js/altcha.js"],
    )


def render_recovery_codes_once_page(username: str, role: str, codes: list[str]) -> str:
    items = "".join(f'<li style="margin-bottom:0.4rem;"><code>{html.escape(c)}</code></li>' for c in codes)
    body = f"""
    <div class="auth-container">
      <section class="card">
        <div class="alert-success">¡Cuenta <strong>{html.escape(username)}</strong> ({html.escape(role)}) activada con éxito!</div>
        <h2>Tus Códigos de Recuperación de Un Solo Uso</h2>
        <p class="muted">Guarda estos 8 códigos en un lugar seguro ahora mismo. Por seguridad solo se muestran esta única vez:</p>
        <ul style="columns:2;list-style:none;padding:0;margin:1rem 0;">
          {items}
        </ul>
        <a href="/auth/login" class="btn" style="width:100%;text-align:center;">Ir a Iniciar Sesión</a>
      </section>
    </div>
    """
    return render_layout("Códigos de Recuperación", body)


def render_trainer_dashboard(
    csrf_token: str,
    username: str,
    entries: list[Any],
    personality_body: str,
    personality_version: int,
    topics: list[Any],
    llm_view: Any,
    posthumous_mode: bool,
    interview_chat_messages: list[Any] | None = None,
    llm_warning: str | None = None,
    flash_msg: str | None = None,
    created_invite_url: str | None = None,
) -> str:
    esc_csrf = html.escape(csrf_token)
    flash_html = f'<div class="alert-success">{html.escape(flash_msg)}</div>' if flash_msg else ""
    llm_warn_html = (
        f'<div class="alert-error"><strong>Aviso de conexión con el modelo LLM:</strong> {html.escape(llm_warning)} '
        f'(Se ha utilizado el banco pre-cargado de entrevista mientras se resuelve la conexión con el proveedor).</div>'
        if llm_warning
        else ""
    )
    invite_box = (
        f'<div class="alert-success"><strong>Enlace de invitación de un solo uso generado:</strong><br>'
        f'<code>{html.escape(created_invite_url)}</code></div>'
        if created_invite_url
        else ""
    )

    chat_bubbles = ""
    for cm in interview_chat_messages or []:
        if cm.sender_role == "interviewer":
            chat_bubbles += f"""
            <div class="card" style="background:#172554;border-color:#3b82f6;padding:1rem;margin-bottom:0.75rem;">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <strong>🤖 Entrevistador IA ({html.escape(llm_view.provider_name.upper())} — {html.escape(llm_view.model_name)})</strong>
                <span class="muted">Tema: {html.escape(cm.topic)}</span>
              </div>
              <div style="white-space:pre-wrap;margin-top:0.4rem;">{html.escape(cm.content)}</div>
            </div>"""
        else:
            saved_badge = (
                f'<span class="badge-external" style="background:#22c55e;color:#052e16;">'
                f'✓ Guardado y cifrado en Base de Conocimiento (Entrada #{cm.saved_entry_id})</span>'
                if cm.saved_entry_id
                else ""
            )
            chat_bubbles += f"""
            <div class="card" style="background:#0b1120;border-color:var(--success);padding:1rem;margin-bottom:0.75rem;">
              <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
                <strong>👤 {html.escape(username)} (Tú)</strong>
                {saved_badge}
              </div>
              <div style="white-space:pre-wrap;margin-top:0.4rem;">{html.escape(cm.content)}</div>
            </div>"""

    entries_rows = ""
    for e in entries:
        entries_rows += f"""
        <div class="card" style="padding:1rem;margin-bottom:0.75rem;background:#0b1120;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong>[{html.escape(e.topic)}]</strong>
            <span class="muted">{html.escape(e.entry_date.strftime("%Y-%m-%d %H:%M"))} ({html.escape(e.status)})</span>
          </div>
          <p style="margin:0.5rem 0;">{html.escape(e.content)}</p>
        </div>"""
    if not entries_rows:
        entries_rows = '<p class="muted">Aún no has guardado entradas en tu base de conocimiento.</p>'

    topics_list = ""
    for t in topics:
        badge = "✓ Cubierto" if t.is_covered else "Pendiente"
        topics_list += (
            f'<li style="margin-bottom:0.4rem;">'
            f'<strong>[{html.escape(t.category)}]</strong> {html.escape(t.prompt_title)} '
            f'<span class="muted">({badge} — ID #{t.id})</span></li>'
        )

    body = f"""
    <h1>Panel del Entrenador ({html.escape(username)})</h1>
    {flash_html}
    {llm_warn_html}
    {invite_box}

    <section class="card" style="border:2px solid var(--accent);">
      <h2>💬 Entrevista Conversacional Guiada por IA ({html.escape(llm_view.provider_name.upper())}: {html.escape(llm_view.model_name)})</h2>
      <p class="muted">
        Conversa libremente con el modelo de IA. <strong>Cada respuesta que envíes se cifra con tu clave personal (DEK) y se guarda automáticamente en tu propia base de conocimiento</strong>, mientras el modelo te guía con nuevas preguntas sobre tu vida, tus ideas y tu forma de hablar.
      </p>
      <div style="max-height:420px;overflow-y:auto;padding-right:0.25rem;margin-bottom:1rem;">
        {chat_bubbles}
      </div>
      <form method="post" action="/trainer/interview-chat" style="margin-bottom:0.85rem;">
        <input type="hidden" name="_csrf_token" value="{esc_csrf}">
        <div class="grid-2" style="margin-bottom:0.75rem;">
          <div>
            <label>Categoría del recuerdo (opcional)</label>
            <input type="text" name="topic" placeholder="Automático según la pregunta actual (ej. infancia, valores, anécdotas)">
          </div>
          <div style="display:flex;align-items:end;padding-bottom:0.4rem;">
            <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;margin:0;">
              <input type="checkbox" name="also_update_personality" value="1" style="width:auto;">
              Usar también esta respuesta para enriquecer mi perfil de personalidad/estilo
            </label>
          </div>
        </div>
        <div class="form-group">
          <label>Tu respuesta al entrevistador IA</label>
          <textarea name="content" rows="3" required placeholder="Responde aquí con tus propias palabras y expresiones habituales..."></textarea>
        </div>
        <button type="submit">Responder y guardar en mi base de conocimiento</button>
      </form>
      <form method="post" action="/trainer/interview-chat/next-question" style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
        <input type="hidden" name="_csrf_token" value="{esc_csrf}">
        <input type="text" name="topic" placeholder="Proponer otro tema (ej. juventud, humor, música, amigos)" style="max-width:340px;">
        <button type="submit" class="btn-secondary">Pedir otra pregunta a la IA</button>
      </form>
    </section>

    <div class="grid-2">
      <section class="card">
        <h2>1. Entrada Manual Directa</h2>
        <p class="muted">Todo texto se cifra con tu clave DEK (AES-256-GCM) antes de guardarse en la BD.</p>
        <form method="post" action="/trainer/entries">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label>Tema (ej. infancia, valores, familia)</label>
            <input type="text" name="topic" required maxlength="120" placeholder="infancia">
          </div>
          <div class="form-group">
            <label>Recuerdo o enseñanza</label>
            <textarea name="content" rows="4" required placeholder="Escribe aquí en primera persona..."></textarea>
          </div>
          <button type="submit">Guardar recuerdo cifrado</button>
        </form>
      </section>

      <section class="card">
        <h2>2. Documento de Personalidad (v{personality_version})</h2>
        <p class="muted">Define tu tono, expresiones habituales, humor y forma de hablar.</p>
        <form method="post" action="/trainer/personality">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label>Descripción de personalidad y estilo</label>
            <textarea name="body" rows="5" required placeholder="Hablo de forma pausada, cercana...">{html.escape(personality_body)}</textarea>
          </div>
          <button type="submit">Guardar nueva versión cifrada</button>
        </form>
      </section>
    </div>

    <div class="grid-2">
      <section class="card">
        <h2>3. Invitar a un Amigo o Albacea</h2>
        <p class="muted">Genera un enlace único de 256 bits con caducidad. No existe registro abierto.</p>
        <form method="post" action="/trainer/invitations">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label>Nombre o referencia del destinatario</label>
            <input type="text" name="recipient_hint" placeholder="Ej. Mi amigo Carlos">
          </div>
          <div class="form-group">
            <label>Rol asignado</label>
            <select name="target_role">
              <option value="amigo">AMIGO (Conversar con mi simulación)</option>
              <option value="entrenador">OTRO ENTRENADOR (Cuenta independiente para replicar su propia personalidad)</option>
              <option value="albacea">ALBACEA (Gestión de continuidad póstuma)</option>
            </select>
          </div>
          <button type="submit">Generar enlace de invitación</button>
        </form>
      </section>

      <section class="card">
        <h2>4. Proveedor LLM ({html.escape(llm_view.provider_name.upper())})</h2>
        <p class="muted">Clave API cifrada en BD: <strong>{"Sí (configurada)" if llm_view.has_api_key_configured else "No"}</strong></p>
        <form method="post" action="/trainer/llm-settings">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label>Proveedor</label>
            <select name="provider_name">
              <option value="openrouter" {"selected" if llm_view.provider_name == "openrouter" else ""}>OpenRouter</option>
              <option value="ollama" {"selected" if llm_view.provider_name == "ollama" else ""}>Ollama Local</option>
              <option value="openai_compatible" {"selected" if llm_view.provider_name == "openai_compatible" else ""}>OpenAI Compatible</option>
            </select>
          </div>
          <div class="form-group">
            <label>URL Base</label>
            <input type="url" name="base_url" value="{html.escape(llm_view.base_url)}" required>
          </div>
          <div class="form-group">
            <label>Modelo</label>
            <input type="text" name="model_name" value="{html.escape(llm_view.model_name)}" required>
          </div>
          <div class="form-group">
            <label>Nueva Clave API (opcional; se cifra con AES-256-GCM y nunca se muestra)</label>
            <input type="password" name="api_key" placeholder="sk-or-v1-...">
          </div>
          <button type="submit">Actualizar proveedor LLM</button>
        </form>
      </section>
    </div>

    <section class="card">
      <h2>5. Modo Entrevista Guiada</h2>
      <ul>{topics_list}</ul>
    </section>

    <section class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
        <h2>6. Recuerdos Guardados ({len(entries)})</h2>
        <form method="post" action="/trainer/export" style="margin:0;">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <input type="hidden" name="format" value="jsonl">
          <button type="submit" class="btn-secondary">Exportar Base a JSONL</button>
        </form>
      </div>
      {entries_rows}
    </section>
    """
    return render_layout(
        "Panel del Entrenador",
        body,
        csrf_token=csrf_token,
        role="entrenador",
        posthumous_mode=posthumous_mode,
    )


def render_friend_dashboard(
    csrf_token: str,
    username: str,
    conversations: list[Any],
    active_conv: Any | None,
    messages: list[Any],
    posthumous_mode: bool,
) -> str:
    esc_csrf = html.escape(csrf_token)
    conv_links = "".join(
        f'<li style="margin-bottom:0.4rem;">'
        f'<a href="/friend/dashboard?conv_id={c.id}" style="color:var(--accent);">'
        f'{html.escape(c.title)}</a></li>'
        for c in conversations
    ) or '<li class="muted">Sin conversaciones aún.</li>'

    chat_section = ""
    if active_conv is not None:
        msg_items = ""
        for m in messages:
            who = "Tú" if m.sender_role == "user" else "Simulación del Entrenador"
            ext_badge = (
                '<span class="badge-external">[Información externa]</span><br>'
                if m.used_web_search
                else ""
            )
            bg = "#0b1120" if m.sender_role == "user" else "#172554"
            msg_items += f"""
            <div class="card" style="background:{bg};padding:0.9rem;margin-bottom:0.75rem;">
              <strong>{who}:</strong><br>
              {ext_badge}
              <div style="white-space:pre-wrap;margin-top:0.35rem;">{html.escape(m.content)}</div>
            </div>"""
        chat_section = f"""
        <section class="card">
          <h2>Conversación: {html.escape(active_conv.title)}</h2>
          <div style="margin-bottom:1rem;">{msg_items or '<p class="muted">Envía el primer mensaje para conversar con la simulación.</p>'}</div>
          <form method="post" action="/friend/conversations/{active_conv.id}/messages">
            <input type="hidden" name="_csrf_token" value="{esc_csrf}">
            <div class="form-group">
              <label>Tu mensaje</label>
              <textarea name="content" rows="3" required placeholder="Escribe aquí tu mensaje..."></textarea>
            </div>
            <button type="submit">Enviar mensaje a la simulación</button>
          </form>
        </section>"""

    body = f"""
    <h1>Conversaciones de {html.escape(username)}</h1>
    <div class="grid-2">
      <section class="card">
        <h2>Mis Hilos Cifrados</h2>
        <ul>{conv_links}</ul>
        <hr style="border-color:var(--border);margin:1rem 0;">
        <form method="post" action="/friend/conversations">
          <input type="hidden" name="_csrf_token" value="{esc_csrf}">
          <div class="form-group">
            <label>Nueva conversación</label>
            <input type="text" name="title" required placeholder="Ej. Recuerdos y consejos">
          </div>
          <button type="submit">Iniciar conversación</button>
        </form>
      </section>
      <div>{chat_section}</div>
    </div>
    """
    return render_layout(
        "Conversaciones",
        body,
        csrf_token=csrf_token,
        role="amigo",
        posthumous_mode=posthumous_mode,
    )
