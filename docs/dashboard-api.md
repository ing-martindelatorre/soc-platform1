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
| `nmap_dashboard_output.html` | Activos, servicios y hallazgos (generado desde `nmap_dashboard.html`) |
| `fortinet_dashboard_output.html` y `fortinet_dashboard_<equipo>.html` | Configuración y políticas por FortiGate |
| `fortinet_threats_dashboard.html` | Amenazas: tráfico, eventos, webfilter, IPS, VPN y antivirus (`?device=<equipo>`; 24 h y 7 d) |
| `snyk_dashboard.html` | Vulnerabilidades por repositorio y aplicación, con descarte |
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
  fija la cookie `soc_session` (`HttpOnly; SameSite=Strict; Path=/`). La sesión
  dura 8 horas y vive en memoria: reiniciar el servidor cierra todas las
  sesiones.
- El token se acepta como cookie `soc_session` o como cabecera `X-SOC-Token`.
- **Todas las páginas** (no solo la API) exigen sesión; sin ella, `GET`
  responde `302` a `/config.html`. Solo `/config.html` y `/favicon.ico` son
  públicos.

## Endpoints

Todos devuelven JSON `{"ok": true|false, …}`. Excepto `login`, exigen
sesión (`401` si falta).

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/config/login` | Inicia sesión |
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
