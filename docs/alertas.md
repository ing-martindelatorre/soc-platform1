# Motor de alertas

Código: `app/alerts/engine.py`. Plantilla del correo:
`dashboard/alert_email_template.html`. Las reglas se guardan en la tabla
`alert_rules` y se administran desde el panel `config.html`.

## Cuándo corre

- `alert_engine_job` del scheduler, cada 5 minutos, ejecuta
  `evaluate_and_send()` (reglas) y `evaluate_job_failures()` (fallos de
  pipeline).
- Es el **único** lugar que evalúa reglas: el dashboard ya no tiene su propio
  hilo de alertas. Si el scheduler no corre, no se envía ninguna alerta,
  aunque el dashboard siga funcionando.

## Reglas (`alert_rules`)

| Campo | Significado |
|---|---|
| `name` | Nombre de la regla |
| `module` | `sentinel`, `fortinet`, `snyk` o `nmap` |
| `condition_field` | Qué consulta usar (ver tabla siguiente) |
| `condition_value` | Valor a buscar (por ejemplo `critical`, `suspicious`) |
| `condition_type` | `match` (basta un evento) o `threshold` (`total_events >= threshold_count`) |
| `threshold_count` | Mínimo de eventos para `threshold` |
| `recipients` | Arreglo de correos |
| `subject` | Asunto base |
| `cooldown_minutes` | Ventana de silencio (por defecto 60) |
| `enabled` | Activa o pausa la regla |
| `device_filter` | Solo Fortinet: limita a un `device_name` |
| `last_sent_at` | Último envío exitoso (informativo) |

### Consultas disponibles

Cada combinación `(módulo, condition_field)` corresponde a una consulta en el
diccionario `QUERIES`. Si no existe, la regla se omite con un `warning`
("Sin query para módulo.campo").

| Módulo | `condition_field` | Qué busca | Ventana |
|---|---|---|---|
| `sentinel` | `classification` | Incidentes con esa clasificación | 1 hora |
| `sentinel` | `severity` | Incidentes con esa severidad | 1 hora |
| `fortinet` | `classification` | `fortinet_threats` con esa clasificación | 1 hora |
| `fortinet` | `source` | `fortinet_threats` de ese origen (`traffic`, `event`…) | 1 hora |
| `fortinet` | `antivirus` | Detecciones de antivirus (`condition_value` se ignora) | 1 hora |
| `snyk` | `severity` | Hallazgos con esa severidad | 24 horas |
| `nmap` | `severity` | Hallazgos con esa severidad | 6 horas |

Todas las consultas devuelven las mismas columnas normalizadas
(`source_label`, `detail`, `severity`, `event_count`, `first_seen`,
`last_seen`, `extra`, `asset_name`) y limitan a 20 grupos. La de antivirus
añade `mailbox` y `mail_sender`.

> **cPanel no tiene consultas** y `MODULE_NAMES` no lo incluye, por lo que no
> se pueden crear reglas para ese módulo sin ampliar el motor.

## Flujo de evaluación

Para cada regla activa:

1. **Cooldown de regla.** Si `last_sent_at` es más reciente que
   `cooldown_minutes`, se salta.
2. **Consulta.** Se ejecuta la query del módulo. Sin filas, no hay alerta.
3. **Umbral.** Con `condition_type = threshold`, se suma `event_count` de
   todas las filas y se compara con `threshold_count`.
4. **Deduplicación por entidad.** Cada fila genera una clave
   `r{rule_id}:{source_label}:{detail}`. Se descartan las claves que ya
   aparecen en `alert_log` con `status = 'sent'` dentro de la ventana de
   `cooldown_minutes`.
5. **Un solo correo.** Si quedan entidades nuevas, se envía **un** correo con
   todas: resumen agregado, tabla de entidades y acciones recomendadas
   (`ACTION_ITEMS` por módulo).
6. **Registro.** Se inserta una fila en `alert_log` por cada entidad nueva
   (no por correo), con `trigger_data` en JSONB y el estado `sent` o `failed`.
7. **Slack.** Si hay `SLACK_WEBHOOK_URL` y el correo salió, se envía además un
   mensaje con adjuntos coloreados por severidad.

Como las entidades fallidas también quedan en `alert_log` (con estado
`failed`), pero la deduplicación solo cuenta `sent`, un correo que no se pudo
enviar se reintenta en el siguiente ciclo.

El asunto se compone como `subject [asset_name] — buzón` (el buzón solo se
añade en alertas de antivirus con buzón resuelto).

## Alertas de fallo de pipeline

`evaluate_job_failures()` busca en `job_runs` las ejecuciones con
`status = 'failed'` de los últimos 10 minutos (la más reciente por job) y
envía un correo a `PIPELINE_ALERT_RECIPIENTS`. Sin esa variable no hace
nada. El cooldown por job (`PIPELINE_ALERT_COOLDOWN`, 60 min) se guarda en
memoria, así que se reinicia con el proceso.

`execute_job` registra como `failed` tanto las excepciones como los
resultados con `ok: False` (cPanel, Fortinet, Nmap y los módulos en
fallback), por lo que ambos casos generan esta alerta. Un fallo parcial
(por ejemplo, un FortiGate de varios) también cuenta como fallo del job.

## Regla incluida

La migración 019 crea la regla "Antivirus Fortinet — Malware detectado"
(`fortinet` / `antivirus`, cooldown 60 min, asunto
`[SOC CRÍTICO] Malware detectado por Fortinet`). Cambia sus destinatarios
desde el panel tras aplicar la migración.

## Severidades y estilos

`SEVERITY_STYLES` define colores e iconos para `critical`, `high`,
`suspicious`, `blocked`, `login_failure`, `medium` y `default`.
`_SEVERITY_RANK` decide qué fila domina el resumen (mayor severidad y luego
mayor número de eventos). Para una severidad nueva, agrégala a ambos.

## Plantilla de correo

`build_email_html` sustituye marcadores `{{…}}` en
`dashboard/alert_email_template.html` (`{{ALERT_TITLE}}`, `{{SEVERITY}}`,
`{{SOURCE_HOST}}`, `{{ENTITIES_TABLE}}`, `{{ACTION_ITEMS}}`, `{{SOC_URL}}`,
`{{MAILBOX_INFO}}`…). Si el archivo no existe, usa una plantilla mínima.

Los valores se insertan **sin escapar HTML**. Los datos provienen de logs
externos (nombres de archivo, remitentes, URLs), así que conviene escapar
con `html.escape` al tocar este código.

## Probar el envío

Desde el panel, botón de prueba SMTP (`POST /api/config/test-smtp`), que envía
un correo de ejemplo a `SMTP_USER`. Por línea de comandos:

```bash
python - <<'PY'
from dotenv import load_dotenv; load_dotenv()
from app.alerts.engine import send_email
print(send_email(["tu@correo.com"], "[SOC] Prueba", "<b>hola</b>"))
PY
```
