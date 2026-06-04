"""
app/alerts/engine.py

Motor de alertas del SOC Platform.
Evalúa reglas configuradas en la DB y envía emails cuando se cumplen.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import urllib.request

from app.core.db import get_connection as db_connect

logger = logging.getLogger("soc-platform")


# =============================================================================
# Email
# =============================================================================

def send_email(recipients: list[str], subject: str, html_body: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASSWORD", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)
    smtp_tls  = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")

    if not smtp_host or not smtp_user:
        logger.warning("[alerts] SMTP no configurado — revisa SMTP_HOST y SMTP_USER en .env")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_from
        msg["To"]      = ", ".join(recipients)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()
        if smtp_port == 465:
            # SSL directo (puerto 465)
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, recipients, msg.as_string())
        elif smtp_tls:
            # STARTTLS (puerto 587)
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, recipients, msg.as_string())

        logger.info(f"[alerts] Email enviado a {recipients} — {subject}")
        return True

    except Exception as e:
        logger.error(f"[alerts] Error enviando email: {e}")
        return False


# =============================================================================
# Template de email
# =============================================================================

TEMPLATE_PATH = Path(__file__).parent.parent.parent / "dashboard" / "alert_email_template.html"

_SLACK_COLORS = {
    "critical": "#c0392b", "high": "#c05a00", "suspicious": "#c07d00",
    "blocked": "#c0392b", "medium": "#8a7200", "login_failure": "#7b00c0",
}


def send_slack_notification(
    webhook_url: str,
    module: str,
    alert_type: str,
    severity: str,
    source_host: str,
    total_events: int,
    first_seen: str,
    last_seen: str,
    rule_name: str,
) -> bool:
    """Envía una notificación a Slack via incoming webhook."""
    color = _SLACK_COLORS.get(severity.lower(), "#1a56db")
    soc_url = os.getenv("SOC_URL", "localhost:8888")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 SOC: {alert_type}",
            "title_link": f"http://{soc_url}/index.html",
            "fields": [
                {"title": "Módulo",        "value": MODULE_NAMES.get(module, module), "short": True},
                {"title": "Severidad",     "value": severity.upper(),                  "short": True},
                {"title": "Origen",        "value": source_host,                       "short": True},
                {"title": "Total eventos", "value": f"{total_events:,}",               "short": True},
                {"title": "Primera det.",  "value": first_seen,                        "short": True},
                {"title": "Última det.",   "value": last_seen,                         "short": True},
            ],
            "footer": f"Leviathan SOC — Regla: {rule_name}",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        logger.error(f"[alerts] Error enviando Slack: {e}")
        return False


# Colores por severidad/clasificación
SEVERITY_STYLES = {
    "critical":     {"color1": "#7b0000", "color2": "#c0392b", "icon": "🚨", "summary_bg": "#fff0f0", "summary_border": "#ff4d6d", "badge_bg": "#ff4d6d", "badge_text": "#fff"},
    "high":         {"color1": "#7a3800", "color2": "#c05a00", "icon": "🔴", "summary_bg": "#fff5f0", "summary_border": "#ff8c42", "badge_bg": "#ff8c42", "badge_text": "#fff"},
    "suspicious":   {"color1": "#7a4d00", "color2": "#c07d00", "icon": "⚠️", "summary_bg": "#fffbf0", "summary_border": "#ffd166", "badge_bg": "#ffd166", "badge_text": "#000"},
    "blocked":      {"color1": "#7b0000", "color2": "#c0392b", "icon": "🚫", "summary_bg": "#fff0f0", "summary_border": "#ff4d6d", "badge_bg": "#ff4d6d", "badge_text": "#fff"},
    "login_failure":{"color1": "#4a007b", "color2": "#7b00c0", "icon": "🔐", "summary_bg": "#f8f0ff", "summary_border": "#bd93f9", "badge_bg": "#bd93f9", "badge_text": "#000"},
    "medium":       {"color1": "#5a4a00", "color2": "#8a7200", "icon": "🟡", "summary_bg": "#fffdf0", "summary_border": "#ffd166", "badge_bg": "#ffd166", "badge_text": "#000"},
    "default":      {"color1": "#0f1923", "color2": "#1a2d47", "icon": "ℹ️", "summary_bg": "#f0f5ff", "summary_border": "#00d4ff", "badge_bg": "#00d4ff", "badge_text": "#000"},
}

MODULE_NAMES = {
    "sentinel":  "SentinelOne",
    "fortinet":  "Fortinet",
    "snyk":      "Snyk",
    "nmap":      "Nmap",
    "scheduler": "Scheduler",
}

ACTION_ITEMS = {
    "sentinel": [
        "Verifica si la amenaza fue mitigada automáticamente",
        "Revisa el equipo afectado con el usuario",
        "Consulta el dashboard de SentinelOne para más detalles",
    ],
    "fortinet": [
        "Revisa el tráfico sospechoso en el dashboard de Fortinet Threats",
        "Verifica si el equipo origen está comprometido",
        "Considera bloquear la conexión si es maliciosa",
    ],
    "snyk": [
        "Revisa el repositorio afectado en el dashboard de Snyk",
        "Actualiza la dependencia vulnerable si hay versión disponible",
        "Evalúa el impacto en los sistemas de producción",
    ],
    "nmap": [
        "Revisa el activo con el hallazgo crítico",
        "Verifica si el puerto/servicio es necesario",
        "Considera cerrar o proteger el servicio expuesto",
    ],
    "scheduler": [
        "Revisa los logs del scheduler para ver el traceback completo",
        "Verifica conectividad con las APIs externas del módulo fallido",
        "Ejecuta el módulo manualmente: python -m app.cli <modulo>",
    ],
}


def build_email_html(
    module: str,
    rule_name: str,
    alert_type: str,
    severity: str,
    source_host: str,
    destination: str,
    description: str,
    alert_datetime: str,
    total_events: int = 1,
    unique_sources: int = 1,
    first_seen: str = "",
    last_seen: str = "",
    entities_table: str = "",
) -> str:
    soc_url  = os.getenv("SOC_URL", "localhost:8888")
    style    = SEVERITY_STYLES.get(severity.lower(), SEVERITY_STYLES["default"])
    mod_name = MODULE_NAMES.get(module, module.capitalize())
    actions  = ACTION_ITEMS.get(module, ACTION_ITEMS["sentinel"])
    action_html = "\n".join(f"<li>{a}</li>" for a in actions)

    try:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        template = "<html><body><pre>{{ALERT_TITLE}}\n{{DESCRIPTION}}\n{{DATETIME}}</pre></body></html>"

    replacements = {
        "{{HEADER_COLOR_1}}":    style["color1"],
        "{{HEADER_COLOR_2}}":    style["color2"],
        "{{SEVERITY_ICON}}":     style["icon"],
        "{{ALERT_TITLE}}":       f"Alerta detectada: {alert_type}",
        "{{SUMMARY_BG}}":        style["summary_bg"],
        "{{SUMMARY_BORDER}}":    style["summary_border"],
        "{{SUMMARY_ICON}}":      style["icon"],
        "{{SUMMARY_STRONG}}":    f"{mod_name}: {alert_type} detectado",
        "{{SUMMARY_DETAIL}}":    f"Requiere revisión inmediata — {total_events:,} evento(s) en {unique_sources} fuente(s)",
        "{{SEV_BADGE_BG}}":      style["badge_bg"],
        "{{SEV_BADGE_TEXT}}":    style["badge_text"],
        "{{SUMMARY_TEXT_STRONG}}": style["summary_border"],
        "{{SUMMARY_TEXT}}":      "#7a4500",
        "{{HIGHLIGHT_COLOR}}":   style["summary_border"],
        "{{MODULE}}":            mod_name,
        "{{ALERT_TYPE}}":        alert_type,
        "{{SEVERITY}}":          severity.upper(),
        "{{SOURCE_HOST}}":       source_host or "—",
        "{{DESTINATION}}":       destination or "—",
        "{{DESCRIPTION}}":       description or "—",
        "{{DATETIME}}":          alert_datetime,
        "{{RULE_NAME}}":         rule_name,
        "{{ACTION_ITEMS}}":      action_html,
        "{{SOC_URL}}":           soc_url,
        "{{TOTAL_EVENTS}}":      f"{total_events:,}",
        "{{UNIQUE_SOURCES}}":    str(unique_sources),
        "{{FIRST_SEEN}}":        first_seen or alert_datetime,
        "{{LAST_SEEN}}":         last_seen or alert_datetime,
        "{{ENTITIES_TABLE}}":    entities_table,
    }

    html = template
    for key, val in replacements.items():
        html = html.replace(key, val)

    return html


# =============================================================================
# Evaluador de reglas
# =============================================================================

# Todas las queries devuelven columnas normalizadas:
#   source_label  — origen único (IP, equipo, repo)
#   detail        — descripción de la amenaza (threat_name, app, título CVE…)
#   severity      — nivel de severidad de ese grupo
#   event_count   — número de eventos agrupados
#   first_seen    — timestamp más antiguo del grupo
#   last_seen     — timestamp más reciente del grupo
#   extra         — dato adicional contextual (país destino, usuario, issue_id…)
QUERIES = {
    "sentinel": {
        "classification": """
            SELECT
                COALESCE(agent_name, '—')            AS source_label,
                COALESCE(threat_name, '—')            AS detail,
                COALESCE(severity, 'unknown')         AS severity,
                COUNT(*)                              AS event_count,
                MIN(created_at)                       AS first_seen,
                MAX(created_at)                       AS last_seen,
                COALESCE(MAX(username), '—')          AS extra
            FROM sentinel_incidents
            WHERE LOWER(COALESCE(classification,'')) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '1 hour'
            GROUP BY agent_name, threat_name, severity
            ORDER BY event_count DESC
            LIMIT 20
        """,
        "severity": """
            SELECT
                COALESCE(agent_name, '—')             AS source_label,
                COALESCE(classification, 'Unknown')   AS detail,
                COALESCE(severity, 'unknown')         AS severity,
                COUNT(*)                              AS event_count,
                MIN(created_at)                       AS first_seen,
                MAX(created_at)                       AS last_seen,
                COALESCE(MAX(username), '—')          AS extra
            FROM sentinel_incidents
            WHERE LOWER(COALESCE(severity,'')) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '1 hour'
            GROUP BY agent_name, classification, severity
            ORDER BY event_count DESC
            LIMIT 20
        """,
    },
    "fortinet": {
        "classification": """
            SELECT
                COALESCE(srcname, srcip, '—')         AS source_label,
                COALESCE(app, classification, '—')    AS detail,
                classification                        AS severity,
                COUNT(*)                              AS event_count,
                MIN(collected_at)                     AS first_seen,
                MAX(collected_at)                     AS last_seen,
                COALESCE(MAX(dstcountry), '—')        AS extra
            FROM fortinet_threats
            WHERE classification = %s
              {device_filter}
              AND collected_at >= NOW() - INTERVAL '1 hour'
            GROUP BY srcname, srcip, app, classification
            ORDER BY event_count DESC
            LIMIT 20
        """,
        "source": """
            SELECT
                COALESCE(srcname, srcip, '—')         AS source_label,
                COALESCE(app, '—')                    AS detail,
                COALESCE(classification, 'info')      AS severity,
                COUNT(*)                              AS event_count,
                MIN(collected_at)                     AS first_seen,
                MAX(collected_at)                     AS last_seen,
                COALESCE(MAX(dstcountry), '—')        AS extra
            FROM fortinet_threats
            WHERE source = %s
              {device_filter}
              AND collected_at >= NOW() - INTERVAL '1 hour'
            GROUP BY srcname, srcip, app, classification
            ORDER BY event_count DESC
            LIMIT 20
        """,
    },
    "snyk": {
        "severity": """
            SELECT
                COALESCE(repo_name, '—')              AS source_label,
                COALESCE(title, '—')                  AS detail,
                COALESCE(severity, 'unknown')         AS severity,
                COUNT(*)                              AS event_count,
                MIN(created_at)                       AS first_seen,
                MAX(created_at)                       AS last_seen,
                COALESCE(MAX(issue_id), '—')          AS extra
            FROM snyk_findings
            WHERE LOWER(severity) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '24 hours'
            GROUP BY repo_name, title, severity
            ORDER BY event_count DESC
            LIMIT 20
        """,
    },
    "nmap": {
        "severity": """
            SELECT
                a.ip                                  AS source_label,
                COALESCE(f.title, '—')                AS detail,
                COALESCE(f.severity, 'unknown')       AS severity,
                COUNT(*)                              AS event_count,
                MIN(f.created_at)                     AS first_seen,
                MAX(f.created_at)                     AS last_seen,
                COALESCE(MAX(f.category), '—')        AS extra
            FROM nmap_findings f
            JOIN nmap_assets a ON f.asset_id = a.id
            WHERE LOWER(f.severity) = LOWER(%s)
              AND f.created_at >= NOW() - INTERVAL '6 hours'
            GROUP BY a.ip, f.title, f.severity
            ORDER BY event_count DESC
            LIMIT 20
        """,
    },
}

_SEVERITY_RANK = {
    "critical": 5, "high": 4, "suspicious": 4, "blocked": 4,
    "medium": 3, "login_failure": 3, "low": 2, "default": 1,
}


def _dedup_key(rule_id: int, row: dict) -> str:
    return f"r{rule_id}:{row.get('source_label','—')}:{row.get('detail','—')}"


def _build_alert_context(rows: list[dict]) -> dict:
    """Construye un resumen agregado a partir de las filas normalizadas."""
    if not rows:
        return {
            "source_host": "—", "destination": "—", "description": "Sin detalles",
            "severity": "info", "total_events": 0, "unique_sources": 0,
            "first_seen": "—", "last_seen": "—",
        }

    total_events   = sum(int(r.get("event_count", 1)) for r in rows)
    sources        = [r.get("source_label", "—") for r in rows]
    unique_sources = len(set(sources))

    # Fila más importante: mayor severidad → mayor count
    top = max(rows, key=lambda r: (
        _SEVERITY_RANK.get(str(r.get("severity", "")).lower(), 0),
        int(r.get("event_count", 0)),
    ))

    # Hasta 3 fuentes únicas en el resumen
    seen: set[str] = set()
    ordered: list[str] = []
    for s in sources:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
        if len(ordered) == 3:
            break
    source_host = ", ".join(ordered)
    if unique_sources > 3:
        source_host += f" (+{unique_sources - 3} más)"

    first_seen = str(min((r["first_seen"] for r in rows if r.get("first_seen")), default="—"))
    last_seen  = str(max((r["last_seen"]  for r in rows if r.get("last_seen")),  default="—"))

    return {
        "source_host":    source_host,
        "destination":    top.get("extra", "—"),
        "description":    top.get("detail", "—"),
        "severity":       str(top.get("severity", "info")),
        "total_events":   total_events,
        "unique_sources": unique_sources,
        "first_seen":     first_seen[:19],
        "last_seen":      last_seen[:19],
    }


def _generate_entities_table(rows: list[dict]) -> str:
    """Genera una tabla HTML con todas las entidades afectadas."""
    if len(rows) <= 1:
        return ""

    td  = "padding:7px 10px;font-size:12px;border-bottom:1px solid #eaeff7;color:#1a1a2e;vertical-align:top"
    tdr = td + ";text-align:right;white-space:nowrap"
    th  = "padding:7px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#8a9bb5;background:#f7f9fc;font-weight:700"
    thr = th + ";text-align:right"

    body = ""
    for r in rows:
        count  = int(r.get("event_count", 1))
        src    = str(r.get("source_label", "—"))
        detail = str(r.get("detail", "—"))[:60]
        first  = str(r.get("first_seen", "—"))[:16]
        last_  = str(r.get("last_seen",  "—"))[:16]
        body += (
            f"<tr>"
            f"<td style='{td}'>{src}</td>"
            f"<td style='{td}'>{detail}</td>"
            f"<td style='{tdr}'><strong>{count:,}</strong></td>"
            f"<td style='{tdr}'>{first}</td>"
            f"<td style='{tdr}'>{last_}</td>"
            f"</tr>"
        )

    return (
        f"<div style='margin:20px 0;border:1px solid #e0e6f0;border-radius:10px;overflow:hidden'>"
        f"<table style='width:100%;border-collapse:collapse'>"
        f"<thead><tr>"
        f"<th style='{th}'>Origen</th>"
        f"<th style='{th}'>Detalle</th>"
        f"<th style='{thr}'>Eventos</th>"
        f"<th style='{thr}'>Primera det.</th>"
        f"<th style='{thr}'>Última det.</th>"
        f"</tr></thead>"
        f"<tbody>{body}</tbody>"
        f"</table></div>"
    )


# Cooldown en memoria para alertas de fallos de pipeline (se resetea al reiniciar)
_pipeline_failure_cooldown: dict[str, datetime] = {}
PIPELINE_ALERT_COOLDOWN_MINUTES = int(os.getenv("PIPELINE_ALERT_COOLDOWN", "60"))


def evaluate_job_failures() -> int:
    """
    Busca pipelines que fallaron en los últimos 10 minutos y envía alertas por email.
    Requiere PIPELINE_ALERT_RECIPIENTS en .env (lista separada por comas).
    Retorna el número de alertas enviadas.
    """
    recipients_raw = os.getenv("PIPELINE_ALERT_RECIPIENTS", "")
    if not recipients_raw:
        return 0

    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        return 0

    sent = 0
    now  = datetime.now(timezone.utc)

    try:
        conn = db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT DISTINCT ON (job_name) job_name, message, started_at
            FROM job_runs
            WHERE status = 'failed'
              AND started_at >= NOW() - INTERVAL '10 minutes'
            ORDER BY job_name, started_at DESC
        """)
        failures = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"[alerts] Error leyendo job_runs: {e}")
        return 0

    for row in failures:
        job_name = row["job_name"]

        last = _pipeline_failure_cooldown.get(job_name)
        if last and (now - last) < timedelta(minutes=PIPELINE_ALERT_COOLDOWN_MINUTES):
            continue

        error_preview = (row.get("message") or "Sin detalles")[:400]
        alert_datetime = str(row.get("started_at", now))

        html = build_email_html(
            module="scheduler",
            rule_name="Pipeline failure",
            alert_type=f"Fallo en pipeline: {job_name}",
            severity="high",
            source_host="soc-platform",
            destination="—",
            description=error_preview,
            alert_datetime=alert_datetime,
        )

        ok = send_email(recipients, f"[SOC] Pipeline fallido: {job_name}", html)
        if ok:
            _pipeline_failure_cooldown[job_name] = now
            sent += 1
            logger.info(f"[alerts] Alerta de fallo enviada para job: {job_name}")

    return sent


def evaluate_and_send() -> int:
    """
    Evalúa todas las reglas activas con deduplicación por entidad.

    Lógica de dedup:
      - Cada evento se agrupa por (origen, detalle) en la query.
      - Se computa un dedup_key por grupo: "r{rule_id}:{source_label}:{detail}"
      - Si ese dedup_key ya fue alertado en alert_log dentro de la ventana
        cooldown_minutes, se omite esa entidad.
      - Si quedan entidades nuevas se envía UN solo correo con todas agrupadas.
      - Se registra una fila en alert_log por entidad nueva (no por email).

    Retorna el número de emails enviados.
    """
    sent = 0

    try:
        conn = db_connect()
        cur  = conn.cursor()

        cur.execute("SELECT * FROM alert_rules WHERE enabled = TRUE ORDER BY id")
        rules = cur.fetchall()

        for rule in rules:
            rule_id         = rule["id"]
            module          = rule["module"]
            field           = rule["condition_field"]
            value           = rule["condition_value"]
            cooldown        = rule["cooldown_minutes"]
            condition_type  = rule.get("condition_type", "match")
            threshold_count = int(rule.get("threshold_count") or 1)

            # ── 1. Obtener eventos agregados ───────────────────────────────────
            query = QUERIES.get(module, {}).get(field)
            if not query:
                logger.warning(f"[alerts] Sin query para {module}.{field}")
                continue

            device_filter = rule.get("device_filter") or ""
            if module == "fortinet":
                if device_filter:
                    query = query.replace("{device_filter}", "AND device_name = %s")
                    params = (value, device_filter)
                else:
                    query = query.replace("{device_filter}", "")
                    params = (value,)
            else:
                params = (value,)

            cur.execute(query, params)
            all_rows = [dict(r) for r in cur.fetchall()]

            if not all_rows:
                continue

            # ── 1b. Verificar umbral de cantidad (condition_type = threshold) ──
            if condition_type == "threshold":
                total = sum(int(r.get("event_count", 0)) for r in all_rows)
                if total < threshold_count:
                    logger.debug(
                        f"[alerts] Regla {rule_id}: umbral no alcanzado ({total}/{threshold_count})"
                    )
                    continue

            # ── 2. Deduplicar por entidad contra alert_log ─────────────────────
            dedup_keys = [_dedup_key(rule_id, r) for r in all_rows]
            cur.execute(
                """
                SELECT DISTINCT dedup_key FROM alert_log
                WHERE dedup_key = ANY(%s)
                  AND sent_at >= NOW() - make_interval(mins => %s)
                  AND status = 'sent'
                """,
                (dedup_keys, cooldown),
            )
            already_alerted = {row["dedup_key"] for row in cur.fetchall()}

            new_rows = [
                r for r in all_rows
                if _dedup_key(rule_id, r) not in already_alerted
            ]

            if not new_rows:
                logger.debug(f"[alerts] Regla {rule_id} ({module}.{field}={value}): todas las entidades ya alertadas")
                continue

            # ── 3. Construir email con contexto agregado ───────────────────────
            ctx            = _build_alert_context(new_rows)
            entities_table = _generate_entities_table(new_rows)
            alert_datetime = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            html = build_email_html(
                module=module,
                rule_name=rule["name"],
                alert_type=value,
                severity=ctx["severity"],
                source_host=ctx["source_host"],
                destination=ctx["destination"],
                description=ctx["description"],
                alert_datetime=alert_datetime,
                total_events=ctx["total_events"],
                unique_sources=ctx["unique_sources"],
                first_seen=ctx["first_seen"],
                last_seen=ctx["last_seen"],
                entities_table=entities_table,
            )

            # ── 4. Enviar email y Slack ────────────────────────────────────────
            recipients = list(rule["recipients"])
            success    = send_email(recipients, rule["subject"], html)
            status     = "sent" if success else "failed"

            slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
            if slack_url and success:
                send_slack_notification(
                    webhook_url=slack_url,
                    module=module,
                    alert_type=value,
                    severity=ctx["severity"],
                    source_host=ctx["source_host"],
                    total_events=ctx["total_events"],
                    first_seen=ctx["first_seen"],
                    last_seen=ctx["last_seen"],
                    rule_name=rule["name"],
                )

            # ── 5. Registrar una fila por entidad nueva en alert_log ──────────
            for r in new_rows:
                dk = _dedup_key(rule_id, r)
                cur.execute(
                    """
                    INSERT INTO alert_log
                        (rule_id, rule_name, module, recipients, subject,
                         trigger_data, status, dedup_key)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    """,
                    (rule_id, rule["name"], module, recipients, rule["subject"],
                     json.dumps(dict(r), default=str), status, dk),
                )

            # ── 6. Actualizar last_sent_at (informativo) ──────────────────────
            if success:
                cur.execute(
                    "UPDATE alert_rules SET last_sent_at = NOW() WHERE id = %s",
                    (rule_id,),
                )
                sent += 1
                logger.info(
                    f"[alerts] Regla {rule['name']}: {len(new_rows)} entidad(es) nuevas, "
                    f"{ctx['total_events']} eventos totales"
                )

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        logger.error(f"[alerts] Error en evaluate_and_send: {e}")

    return sent
