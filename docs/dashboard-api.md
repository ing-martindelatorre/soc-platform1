# Dashboard y API

`dashboard/server.py` es un servidor único (`ThreadingHTTPServer`, biblioteca
estándar) que sirve todos los dashboards y la API de configuración. Puerto
por defecto: **8888** (`DASHBOARD_PORT`), interfaz `0.0.0.0` (`DASHBOARD_HOST`).

```bash
python dashboard/server.py
```

Con `SSL_CERT_FILE` y `SSL_KEY_FILE` definidos sirve por HTTPS; sin ellos, por
HTTP y muestra una advertencia al arrancar.

## Páginas

| Archivo | Contenido |
|---|---|
| `index.html` | Portal con tarjetas por módulo y semáforo de salud (lee `soc_status.json`) |
| `sentinel_dashboard_simple.html` | Incidentes de SentinelOne (lee `sentinel_dashboard_data.json`) |
| `nmap_dashboard_output.html` | Vulnerabilidades reales (CVE, KEV, confirmadas por NSE), activos, servicios y hallazgos de exposición (generado desde `nmap_dashboard.html`) |
| `fortinet_dashboard_output.html` y `fortinet_dashboard_<equipo>.html` | Configuración y políticas por FortiGate |
| `fortinet_threats_dashboard.html` | Amenazas: tráfico, eventos, webfilter, IPS, VPN y antivirus (`?device=<equipo>`; 24 h y 7 d) |
| `snyk_dashboard.html` | Vulnerabilidades por repositorio y aplicación, con descarte. Solo muestra los repos en scope (`ambiente=produccion`, leídos de `repos_snyk_batch.txt`); los hallazgos de repos fuera de scope siguen en BD pero no se muestran. El resumen por proyecto y el detalle por aplicación listan siempre todos los repos en scope con un estado (`con hallazgos`, `limpio` con ceros, `pending` si nunca se ha escaneado, `error`, `sin proyecto soportado`) calculado del último registro en `snyk_scan_runs` |
| `cpanel_dashboard.html` | Estado del servidor, correo, spam y virus, cuentas |
| `config.html` | Login y panel de configuración (reglas, intervalos, log de alertas) |

Los HTML `*_output.html` y `fortinet_dashboard_<equipo>.html` los **genera**
el servidor reemplazando `{{DATA}}` en la plantilla. Los `*.json` de datos
están en `.gitignore`.

## Hilos de refresco

| Hilo | Intervalo (variable) | Produce |
|---|---|---|
| `sentinel` | 30 s (`DASH_REFRESH_SENTINEL`) | `sentinel_dashboard_data.json` |
| `nmap` | 300 s (`DASH_REFRESH_NMAP`) | `nmap_dashboard_output.html` |
| `fortinet` | 60 s (`DASH_REFRESH_FORTINET`) | `fortinet_dashboard_*.html` |
| `fortinet-threats` | 120 s (`DASH_REFRESH_FORTINET_THREATS`) | `fortinet_threats_data[_<equipo>][_7d].json` |
| `snyk` | 300 s (`DASH_REFRESH_SNYK`) | `snyk_dashboard_data.json` |
| `cpanel` | 300 s (`DASH_REFRESH_CPANEL`) | `cpanel_dashboard_data.json` |
| `index-status` | 5 s | `soc_status.json` |
| `forti-cleanup` | 24 h | Borra `fortinet_threats` de más de 1 año |
| `http` | — | Sirve las páginas y la API |

`soc_status.json` alimenta el semáforo: por módulo guarda `status`
(`pending`, `ok` o `error`), `last_update`, `records` y un bloque `health`
con contadores (por ejemplo `critical_findings` en Nmap o `cpu_load_1` en
cPanel).

Los equipos Fortinet se derivan de las variables `FORTI_<n>_*`. Para cada uno
se generan archivos con el nombre en minúsculas y con `_` en lugar de
espacios y guiones (`San Martin` → `san_martin`).

## Autenticación

- El acceso lo controla `CONFIG_USER` y `CONFIG_PASSWORD`. **Si no están
  definidas, el login responde 503** y nada se puede usar.
- `POST /api/config/login` con `{"username", "password"}` devuelve un token y
  fija la cookie `soc_session_<DASHBOARD_PORT>` (`HttpOnly; SameSite=Strict;
  Path=/; Max-Age=28800`). El puerto va en el nombre porque las cookies no se
  aíslan por puerto: dos instancias en el mismo host con el mismo nombre de
  cookie se cerraban la sesión mutuamente. La sesión dura 8 horas y vive en
  memoria: reiniciar el servidor cierra todas las sesiones.
- El token se acepta como cookie `soc_session_<puerto>` o como cabecera `X-SOC-Token`.
- **Todas las páginas** (no solo la API) exigen sesión. Sin ella, un `GET` a
  una página `.html` responde `302` a `/config.html?next=<ruta>` (tras el login
  se vuelve a esa ruta) y un `GET` a datos (`*.json`, `*.csv`…) responde `401`,
  que las páginas detectan para mandar al login. Solo `/config.html` y
  `/favicon.ico` son públicos.
- Todas las respuestas llevan `Cache-Control: no-store`.

## Endpoints

Todos devuelven JSON `{"ok": true|false, …}`. Excepto `login`, `logout` y `session`, exigen
sesión (`401` si falta).

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/config/login` | Inicia sesión |
| POST | `/api/config/logout` | Cierra la sesión y borra la cookie |
| GET | `/api/config/session` | `200` si la sesión es válida, `401` si no |
| GET | `/api/config/rules` | Lista reglas de alerta |
| POST | `/api/config/rules` | Crea una regla |
| PUT | `/api/config/rules/<id>` | Reemplaza una regla |
| PATCH | `/api/config/rules/<id>` | Activa o desactiva (`{"enabled": bool}`) |
| DELETE | `/api/config/rules/<id>` | Elimina una regla |
| GET | `/api/config/schedules` | Lista `job_config` con la última ejecución (`last_run`) |
| PUT | `/api/config/schedules/<job_id>` | Cambia intervalo o estado |
| GET | `/api/config/alert-log` | Últimas 100 alertas |
| POST | `/api/config/test-smtp` | Envía un correo de prueba a `SMTP_USER` |
| POST | `/api/dismissals` | Descarta o reactiva un hallazgo de Snyk |
| GET | `/api/config/exec-reports` | Lista los reportes ejecutivos (sin el HTML) con su último envío, y la config de envío automático |
| GET | `/api/config/exec-reports/<id>/html` | HTML del reporte listo (`?download=1` lo descarga). Responde `text/html` con CSP sin scripts |
| POST | `/api/config/exec-reports/generate` | `{"period": "AAAA-MM"}`; lanza la generación en un hilo y devuelve `id` y `started` (`false` si ya se estaba generando) |
| POST | `/api/config/exec-reports/<id>/send` | `{"recipients": "a@x.com, b@x.com"}`; envía el reporte por SMTP |
| PUT | `/api/config/exec-reports-config` | `{"enabled", "recipients", "send_day", "send_hour"}` del envío automático |
| DELETE | `/api/config/exec-reports/<id>` | Elimina un reporte y su historial de envíos |

### Reportes ejecutivos

Pestaña **Reportes Ejecutivos** del panel. `app/reports/executive.py` agrega el
mes (hora de México) de FortiGate, SentinelOne, Snyk (repos en scope, sin
descartados), Nmap y cPanel, prioriza las amenazas en lenguaje de negocio y arma
un HTML compatible con clientes de correo (gráficas hechas con tablas, sin JS ni
imágenes). La agregación de `fortinet_threats` recorre millones de filas, por eso
la generación corre en segundo plano (≈30 s–4 min) y el resultado se guarda en
`executive_reports`. Si se genera el mes en curso, el reporte sale marcado como
parcial. La comparación con el mes anterior usa el reporte guardado de ese mes;
si no existe se recalcula, pero Fortinet solo se compara si la retención (60
días) aún cubre ese mes completo.

El reporte incluye además la sección **Comparación con meses anteriores**:
columnas por mes (hasta 12, incluido el del reporte) de amenazas bloqueadas,
incidentes de SentinelOne y vulnerabilidades críticas/altas abiertas, con el
mes contra el promedio de los anteriores. Cada mes sale del reporte guardado de
ese mes (generado ya cerrado); SentinelOne se recalcula en vivo si su retención
aún cubre el mes. Por la retención corta de Fortinet, el histórico de bloqueos
se va llenando conforme se generan reportes mensuales; los meses iniciales sin
datos se omiten y una serie con menos de 2 meses no se grafica.

### Crear o editar una regla

Campos requeridos: `name`, `module`, `condition_field`, `condition_value`,
`recipients` (arreglo), `subject`. Opcionales: `condition_type` (`match` por
defecto), `threshold_count` (1), `cooldown_minutes` (60).

```json
{
  "name": "Críticos de Snyk",
  "module": "snyk",
  "condition_field": "severity",
  "condition_value": "critical",
  "recipients": ["seguridad@empresa.com"],
  "subject": "SOC: vulnerabilidad crítica",
  "condition_type": "threshold",
  "threshold_count": 3,
  "cooldown_minutes": 360
}
```

`device_filter` **no se puede establecer desde la API ni desde el panel**;
hay que escribirlo directamente en la tabla.

### Cambiar un intervalo

```http
PUT /api/config/schedules/sentinel_job
{"schedule_type": "interval", "schedule_value": "10", "enabled": true}
```

`schedule_type` es `interval` (minutos, 1 a 10080) o `cron` (crontab de cinco
campos, zona `America/Mexico_City`). Un valor inválido devuelve `400` con el
motivo. El cambio se guarda en `job_config` y el scheduler lo aplica en un
máximo de 30 s.

### Descartar un hallazgo de Snyk

```http
POST /api/dismissals
{"action": "dismiss", "repo_name": "WebAPI", "issue_id": "SNYK-…",
 "reason": "Falso positivo: no se usa en producción", "dismissed_by": "mtorre"}
```

`action` es `dismiss` (requiere `reason`) o `reactivate`. Tras el cambio se
regenera el JSON del dashboard de Snyk.

## Seguridad: consideraciones

- CORS está desactivado salvo que se defina `CORS_ORIGIN`.
- Las contraseñas del panel se comparan con `==` y las sesiones no tienen
  bandera `Secure`. Sírvelo tras HTTPS y en una red interna.
- Sin `SSL_CERT_FILE`, las credenciales viajan en claro.
- El servidor no limita intentos de login.

Más en [problemas-conocidos.md](problemas-conocidos.md).

## Ejecución independiente de dashboards

Los scripts `dashboard/run_<módulo>_dashboard.py` generan o sirven un
dashboard por separado (útil para depurar). `run_snyk_dashboard.py` levanta su
propio servidor en `SNYK_DASHBOARD_PORT` (8010); no forman parte del flujo
normal, donde `server.py` importa sus funciones.
