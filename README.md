# MCP Email IMAP/SMTP

Servidor Model Context Protocol (MCP) para que agentes IA consulten correos por IMAP y envien correos por SMTP sin conocer credenciales.

## Caracteristicas

- Multiples cuentas nombradas mediante variables de entorno.
- Lectura IMAP: listar carpetas, buscar correos, leer mensajes y descargar adjuntos bajo limite.
- Envio SMTP en dos pasos: `prepare_email` genera un `send_token`; `send_prepared_email` envia solo si recibe el mismo contenido y token valido.
- Operaciones IMAP adicionales: mover mensajes, eliminar por criterios con token, guardar borradores y crear carpetas.
- Credenciales nunca se aceptan como parametros de herramientas MCP.
- Logs JSON sin passwords, tokens, cuerpos completos ni adjuntos.

## Herramientas Disponibles

- `list_accounts`: lista cuentas disponibles y capacidades sin secretos.
- `list_mailboxes`: lista carpetas IMAP de una cuenta.
- `search_emails`: busca mensajes con filtros y limite seguro.
- `get_email`: obtiene asunto, remitentes, destinatarios, fecha, cuerpo limitado y metadatos de adjuntos.
- `get_attachment`: devuelve un adjunto en Base64 si no supera `MAX_ATTACHMENT_BYTES`.
- `prepare_email`: prepara un mensaje y devuelve `send_token`; no envia.
- `send_prepared_email`: envia por SMTP si el payload coincide exactamente con el token.
- `prepare_delete_messages`: prepara un borrado seguro y devuelve `delete_token`.
- `email_delete_messages`: elimina mensajes por criterios solo si el token coincide con el payload exacto.
- `email_move_message`: mueve un mensaje entre carpetas IMAP.
- `email_save_draft`: guarda un borrador en la carpeta elegida.
- `email_create_folder`: crea una carpeta IMAP.
- `email_mark_messages`: marca mensajes como leidos, no leidos, destacados o no destacados.
- `email_reply`: prepara o envia una respuesta con token de confirmacion.
- `email_forward`: prepara o envia un reenvio con token de confirmacion.
- `email_archive_messages`: archiva mensajes por criterios con token de confirmacion.
- `email_summarize_thread_data`: devuelve datos ordenados de un hilo para que el agente lo resuma.
- `email_search_threads`: busca mensajes agrupados por conversacion.
- `email_get_recent_attachments`: encuentra adjuntos recientes por remitente, asunto o extension.
- `email_extract_structured`: extrae emails, montos, identificaciones, telefonos, links y numeros de factura.
- `email_apply_rules_preview`: previsualiza reglas de movimiento por criterios.
- `email_apply_rules`: aplica reglas previsualizadas con token de confirmacion.
- `email_watch_mailbox`: devuelve mensajes nuevos desde el ultimo UID visto.
- `email_test_account`: prueba conectividad IMAP/SMTP sin exponer credenciales.
- `email_find_unsubscribe_links`: detecta enlaces de baja en headers y cuerpo del mensaje.

## Configuracion

Este servidor es stateless. Copia `.env.example` a `.env` y completa los valores reales. Nunca hagas commit de `.env`.

```env
EMAIL_ACCOUNTS=personal,trabajo
EMAIL_PERSONAL_IMAP_HOST=imap.example.com
EMAIL_PERSONAL_IMAP_PORT=993
EMAIL_PERSONAL_IMAP_USER=user@example.com
EMAIL_PERSONAL_IMAP_PASSWORD=...
EMAIL_PERSONAL_SMTP_HOST=smtp.example.com
EMAIL_PERSONAL_SMTP_PORT=587
EMAIL_PERSONAL_SMTP_USER=user@example.com
EMAIL_PERSONAL_SMTP_PASSWORD=...
EMAIL_PERSONAL_FROM=user@example.com
EMAIL_PERSONAL_TLS_MODE=starttls
MCP_MASTER_KEY=...
```

Genera `MCP_MASTER_KEY` con:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Docker

```bash
docker build -t mcp-email .
docker run --rm -i --env-file .env mcp-email
```

## Claude Desktop

```json
{
  "mcpServers": {
    "mcp-email": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env-file",
        "/ruta/absoluta/a/comunicaciones/email/.env",
        "mcp-email"
      ]
    }
  }
}
```

## Seguridad

- Usa contrasenas de aplicacion cuando el proveedor lo permita.
- Restringe el `.env` con `chmod 600 .env`.
- El agente puede ver contenido de correo y adjuntos solicitados, pero nunca credenciales IMAP/SMTP.
