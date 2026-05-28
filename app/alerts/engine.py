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

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("soc-platform")

# ============================================================================ =
# DB
# =============================================================================

def db_connect():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        cursor_factory=RealDictCursor,
    )


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
    "sentinel": "SentinelOne",
    "fortinet": "Fortinet",
    "snyk":     "Snyk",
    "nmap":     "Nmap",
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
) -> str:
    soc_url  = os.getenv("SOC_URL", "localhost:8888")
    style    = SEVERITY_STYLES.get(severity.lower(), SEVERITY_STYLES["default"])
    mod_name = MODULE_NAMES.get(module, module.capitalize())
    actions  = ACTION_ITEMS.get(module, ACTION_ITEMS["sentinel"])
    action_html = "\n".join(f"<li>{a}</li>" for a in actions)

    try:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Template de fallback si no existe el archivo
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
        "{{SUMMARY_DETAIL}}":    f"Requiere revisión inmediata por parte del equipo de TI",
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
    }

    html = template
    for key, value in replacements.items():
        html = html.replace(key, value)

    return html


# =============================================================================
# Evaluador de reglas
# =============================================================================

QUERIES = {
    "sentinel": {
        "classification": """
            SELECT threat_name, agent_name, username, classification, severity, created_at
            FROM sentinel_incidents
            WHERE LOWER(COALESCE(classification,'')) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '1 hour'
            ORDER BY created_at DESC LIMIT 5
        """,
        "severity": """
            SELECT threat_name, agent_name, username, classification, severity, created_at
            FROM sentinel_incidents
            WHERE LOWER(COALESCE(severity,'')) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '1 hour'
            ORDER BY created_at DESC LIMIT 5
        """,
    },
    "fortinet": {
        "classification": """
            SELECT srcip, srcname, dstip, dstcountry, app, classification, collected_at
            FROM fortinet_threats
            WHERE classification = %s
              AND collected_at >= NOW() - INTERVAL '1 hour'
            ORDER BY collected_at DESC LIMIT 5
        """,
        "source": """
            SELECT srcip, srcname, dstip, dstcountry, app, classification, collected_at
            FROM fortinet_threats
            WHERE source = %s
              AND collected_at >= NOW() - INTERVAL '1 hour'
            ORDER BY collected_at DESC LIMIT 5
        """,
    },
    "snyk": {
        "severity": """
            SELECT repo_name, title, severity, issue_id, created_at
            FROM snyk_findings
            WHERE LOWER(severity) = LOWER(%s)
              AND created_at >= NOW() - INTERVAL '24 hours'
            ORDER BY created_at DESC LIMIT 5
        """,
    },
    "nmap": {
        "severity": """
            SELECT a.ip, f.title, f.severity, f.category, f.created_at
            FROM nmap_findings f JOIN nmap_assets a ON f.asset_id = a.id
            WHERE LOWER(f.severity) = LOWER(%s)
              AND f.created_at >= NOW() - INTERVAL '6 hours'
            ORDER BY f.created_at DESC LIMIT 5
        """,
    },
}


def _format_trigger_data(module: str, rows: list[dict]) -> tuple[str, str, str, str]:
    """Extrae source_host, destination, description y severity de los rows."""
    if not rows:
        return "—", "—", "Sin detalles", "info"

    r = rows[0]

    if module == "sentinel":
        return (
            r.get("agent_name") or "—",
            "—",
            r.get("threat_name") or "—",
            r.get("severity") or "info",
        )
    elif module == "fortinet":
        return (
            r.get("srcname") or r.get("srcip") or "—",
            f"{r.get('dstip','—')} ({r.get('dstcountry','?')})",
            r.get("app") or r.get("classification") or "—",
            r.get("classification") or "info",
        )
    elif module == "snyk":
        return (
            r.get("repo_name") or "—",
            "—",
            r.get("title") or "—",
            r.get("severity") or "info",
        )
    elif module == "nmap":
        return (
            r.get("ip") or "—",
            "—",
            r.get("title") or "—",
            r.get("severity") or "info",
        )
    return "—", "—", "—", "info"


def evaluate_and_send() -> int:
    """
    Evalúa todas las reglas activas y envía alertas si corresponde.
    Retorna el número de alertas enviadas.
    """
    sent = 0

    try:
        conn = db_connect()
        cur  = conn.cursor()

        cur.execute("SELECT * FROM alert_rules WHERE enabled = TRUE ORDER BY id")
        rules = cur.fetchall()

        for rule in rules:
            rule_id    = rule["id"]
            module     = rule["module"]
            field      = rule["condition_field"]
            value      = rule["condition_value"]
            cooldown   = rule["cooldown_minutes"]
            last_sent  = rule["last_sent_at"]

            # Verificar cooldown
            if last_sent:
                elapsed = datetime.now(timezone.utc) - last_sent
                if elapsed < timedelta(minutes=cooldown):
                    continue

            # Buscar eventos que cumplan la condición
            query = QUERIES.get(module, {}).get(field)
            if not query:
                logger.warning(f"[alerts] Sin query para {module}.{field}")
                continue

            cur.execute(query, (value,))
            rows = [dict(r) for r in cur.fetchall()]

            if not rows:
                continue

            # Construir email
            source_host, destination, description, severity = _format_trigger_data(module, rows)
            alert_datetime = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            html = build_email_html(
                module=module,
                rule_name=rule["name"],
                alert_type=value,
                severity=severity,
                source_host=source_host,
                destination=destination,
                description=description,
                alert_datetime=alert_datetime,
            )

            # Enviar email
            recipients = list(rule["recipients"])
            success = send_email(recipients, rule["subject"], html)
            status  = "sent" if success else "failed"

            # Registrar en log
            cur.execute(
                """
                INSERT INTO alert_log (rule_id, rule_name, module, recipients, subject, trigger_data, status)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
                """,
                (rule_id, rule["name"], module, recipients, rule["subject"],
                 json.dumps([dict(r) for r in rows], default=str), status),
            )

            # Actualizar last_sent_at
            if success:
                cur.execute(
                    "UPDATE alert_rules SET last_sent_at = NOW() WHERE id = %s",
                    (rule_id,)
                )
                sent += 1

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        logger.error(f"[alerts] Error en evaluate_and_send: {e}")

    return sent
