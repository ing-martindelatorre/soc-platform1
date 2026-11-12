"""
app/reports/executive.py

Reporte ejecutivo mensual de amenazas, pensado para gerentes: pocas cifras,
lenguaje de negocio y gráficas de barras simples.

- collect_report_data()  → agrega las métricas del mes desde PostgreSQL
- build_report_html()    → arma un HTML compatible con clientes de correo
                           (las gráficas son tablas, no JS ni imágenes)
- start_generation() / build_and_store() → guardan el reporte en executive_reports
- send_report()          → lo envía por SMTP y registra el envío
- run_monthly_job()      → envío automático (lo llama el scheduler cada hora)

La agregación de fortinet_threats recorre millones de filas (~45 s por mes),
por eso el reporte se genera en segundo plano y se guarda; el mes anterior se
compara contra su reporte guardado en vez de recalcularlo.
"""
from __future__ import annotations

import html
import json
import logging
import os
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from app.core.db import get_connection

logger = logging.getLogger("soc-platform")

TZ_NAME = "America/Mexico_City"
TZ      = ZoneInfo(TZ_NAME)

# Batch con los repos de Snyk en scope (mismo criterio que el dashboard de Snyk)
SNYK_SCOPE_BATCH = Path(__file__).resolve().parent.parent.parent / "repos_snyk_batch.txt"

MONTHS_ES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
             "agosto", "septiembre", "octubre", "noviembre", "diciembre"]

# Una generación que lleva más de esto en "generating" se considera abandonada
# (p.ej. el dashboard se reinició a la mitad) y se puede relanzar.
STALE_GENERATION_MINUTES = 20

# Máximo de intentos automáticos por mes, para no reintentar cada hora sin fin
MAX_AUTO_ATTEMPTS = 3

# Las métricas "foto" (vulnerabilidades abiertas, pendientes) de un reporte
# guardado solo sirven de comparación si se generó a lo más N días tras el cierre
SNAPSHOT_MAX_DAYS = 10

# Comparación histórica: meses mostrados (incluye el del reporte) y KPIs graficados
HISTORY_MONTHS = 12
HISTORY_KEYS   = ("blocked", "incidents", "open_risks")


# =============================================================================
# Fechas
# =============================================================================

def parse_period(value: str | date | None) -> date:
    """'2026-10' / '2026-10-01' / date → primer día del mes. None = mes anterior."""
    if value is None:
        today = datetime.now(TZ).date()
        year, month = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
        return date(year, month, 1)
    if isinstance(value, date):
        return value.replace(day=1)
    m = re.fullmatch(r"(\d{4})-(\d{2})(?:-\d{2})?", str(value).strip())
    if not m or not 1 <= int(m.group(2)) <= 12:
        raise ValueError("Periodo inválido, usa el formato AAAA-MM")
    return date(int(m.group(1)), int(m.group(2)), 1)


def _next_month(d: date) -> date:
    return date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)


def _prev_month(d: date) -> date:
    return date(d.year - 1, 12, 1) if d.month == 1 else date(d.year, d.month - 1, 1)


def month_bounds(period: date) -> tuple[datetime, datetime]:
    """Inicio y fin (exclusivo) del mes en hora de México, como datetimes con zona."""
    start = datetime(period.year, period.month, 1, tzinfo=TZ)
    nxt   = _next_month(period)
    end   = datetime(nxt.year, nxt.month, 1, tzinfo=TZ)
    return start, end


def period_label(period: date) -> str:
    return f"{MONTHS_ES[period.month - 1].capitalize()} {period.year}"


def _naive_utc(dt: datetime) -> datetime:
    """Para columnas TIMESTAMP sin zona que guardan UTC (nmap_findings)."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


# =============================================================================
# Traducción a lenguaje de negocio
# =============================================================================

FORTI_CATEGORIES = {
    # clave: (etiqueta para gerentes, cuenta como "amenaza bloqueada")
    "firewall":   ("Conexiones maliciosas bloqueadas por el firewall", True),
    "web":        ("Sitios web peligrosos o no permitidos bloqueados", True),
    "antivirus":  ("Archivos con virus bloqueados", True),
    "intrusion":  ("Intentos de intrusión detenidos", True),
    "sospechoso": ("Tráfico sospechoso detectado", False),
    "login":      ("Intentos fallidos de acceso a los firewalls", False),
    "critico":    ("Eventos críticos en los firewalls", False),
}

SENTINEL_CLASSES = {
    "ransomware":  "Ransomware (secuestro de información)",
    "malware":     "Malware",
    "trojan":      "Troyano",
    "hacktool":    "Herramientas de hackeo",
    "cryptominer": "Minado de criptomonedas",
    "pua":         "Programas no deseados",
    "exploit":     "Explotación de vulnerabilidades",
    "general":     "Amenaza genérica",
    "benign":      "Falso positivo (benigno)",
}

# Familias de malware frecuentes en los logs de antivirus del FortiGate
VIRUS_FAMILIES = {
    "formbook":   "robo de contraseñas e información (FormBook)",
    "agenttesla": "robo de contraseñas e información (Agent Tesla)",
    "lokibot":    "robo de contraseñas e información (LokiBot)",
    "snakekeylogger": "registro de teclas y robo de contraseñas (Snake Keylogger)",
    "xworm":      "control remoto del equipo (XWorm)",
    "remcos":     "control remoto del equipo (Remcos)",
    "asyncrat":   "control remoto del equipo (AsyncRAT)",
    "njrat":      "control remoto del equipo (njRAT)",
    "emotet":     "descarga de otros programas maliciosos (Emotet)",
    "qakbot":     "descarga de otros programas maliciosos (Qakbot)",
    "phish":      "suplantación de identidad (phishing)",
}

# Nombres típicos de activadores/cracks: delatan software sin licencia
PIRACY_PATTERN = re.compile(r"kms|oinstall|activat|crack|keygen|patch|loader|autopico", re.I)

NMAP_SERVICES = {
    "rdp":   "Escritorio remoto (RDP)",
    "3389":  "Escritorio remoto (RDP)",
    "smb":   "Carpetas compartidas de Windows (SMB)",
    "445":   "Carpetas compartidas de Windows (SMB)",
    "ftp":   "Transferencia de archivos sin cifrar (FTP)",
    "21":    "Transferencia de archivos sin cifrar (FTP)",
    "telnet": "Acceso remoto sin cifrar (Telnet)",
    "23":    "Acceso remoto sin cifrar (Telnet)",
    "3306":  "Base de datos MySQL",
    "mysql": "Base de datos MySQL",
    "1433":  "Base de datos SQL Server",
    "5432":  "Base de datos PostgreSQL",
    "22":    "Acceso remoto SSH",
    "ssh":   "Acceso remoto SSH",
    "vnc":   "Control remoto VNC",
    "5900":  "Control remoto VNC",
}


def describe_virus(name: str) -> str:
    low = (name or "").lower()
    for key, desc in VIRUS_FAMILIES.items():
        if key in low:
            return desc
    if "exploit" in low or "cve" in low:
        return "documento que aprovecha una falla de Office/Windows"
    if low.endswith("!tr") or "trojan" in low:
        return f"troyano ({name})"
    return f"malware ({name})"


def describe_ips_attack(name: str) -> str:
    low = (name or "").lower()
    if "eqnedt32" in low or "ms.office" in low:
        return "documentos de Office maliciosos que aprovechan una falla conocida"
    if "botnet" in low:
        return "equipos intentando comunicarse con una red de bots (botnet)"
    if "brute" in low or "login" in low:
        return "intentos de adivinar contraseñas"
    if "scan" in low:
        return "escaneos en busca de puntos débiles"
    return name


def describe_nmap_title(title: str) -> str:
    """'Servicio sensible detectado: rdp' / 'Puerto sensible detectado: 3389/tcp' → nombre entendible."""
    tail = (title or "").split(":")[-1].strip().lower()
    key  = tail.split("/")[0]
    return NMAP_SERVICES.get(key, title)


def _fmt(n: int | float | None) -> str:
    if n is None:
        return "—"
    return f"{int(n):,}"


# =============================================================================
# Recolección de datos
# =============================================================================

def _fortinet_data(cur, start: datetime, end: datetime, details: bool = True) -> dict:
    """
    Una sola pasada sobre fortinet_threats agrupando por categoría y por
    (día | país destino | categoría web) con GROUPING SETS.
    """
    cur.execute("""
        WITH t AS (
            SELECT (collected_at AT TIME ZONE %(tz)s)::date AS d,
                   CASE
                       WHEN source = 'antivirus'                                   THEN 'antivirus'
                       WHEN source = 'ips'                                         THEN 'intrusion'
                       WHEN source = 'traffic'   AND classification = 'blocked'    THEN 'firewall'
                       WHEN source = 'traffic'   AND classification = 'suspicious' THEN 'sospechoso'
                       WHEN source = 'webfilter' AND classification = 'blocked'    THEN 'web'
                       WHEN classification = 'login_failure'                       THEN 'login'
                       WHEN classification = 'critical'                            THEN 'critico'
                   END AS cat,
                   dstcountry, catdesc
            FROM fortinet_threats
            WHERE collected_at >= %(start)s AND collected_at < %(end)s
              AND (classification IN ('blocked', 'suspicious', 'login_failure', 'critical')
                   OR source IN ('antivirus', 'ips'))
        )
        SELECT cat, d, dstcountry, catdesc, GROUPING(d, dstcountry, catdesc) AS g, COUNT(*) AS n
        FROM t
        WHERE cat IS NOT NULL
        GROUP BY GROUPING SETS ((cat, d), (cat, dstcountry), (cat, catdesc))
    """, {"tz": TZ_NAME, "start": start, "end": end})

    totals: dict[str, int]    = {k: 0 for k in FORTI_CATEGORIES}
    by_day: dict[date, int]   = {}
    countries: dict[str, int] = {}
    web_cats: dict[str, int]  = {}
    for r in cur.fetchall():
        cat, n = r["cat"], r["n"]
        if r["g"] == 3:      # (cat, d)
            totals[cat] += n
            if FORTI_CATEGORIES[cat][1]:
                by_day[r["d"]] = by_day.get(r["d"], 0) + n
        elif r["g"] == 5:    # (cat, dstcountry)
            c = r["dstcountry"]
            if cat in ("firewall", "sospechoso") and c and c not in ("Reserved", "N/A"):
                countries[c] = countries.get(c, 0) + n
        elif r["g"] == 6:    # (cat, catdesc)
            if cat == "web" and r["catdesc"]:
                web_cats[r["catdesc"]] = web_cats.get(r["catdesc"], 0) + n

    data = {
        "available": True,
        "totals":    totals,
        "blocked":   sum(n for k, n in totals.items() if FORTI_CATEGORIES[k][1]),
    }
    if not details:
        return data

    # Semanas del mes: 1–7, 8–14, 15–21, 22–28, 29–fin
    weeks = []
    last_day = (end.date() - start.date()).days
    for first in range(1, last_day + 1, 7):
        last = min(first + 6, last_day)
        total = sum(n for d, n in by_day.items() if first <= d.day <= last)
        weeks.append({"label": f"{first}–{last}", "total": total})
    data["weeks"] = weeks
    data["top_countries"] = sorted(countries.items(), key=lambda x: -x[1])[:5]
    data["top_web"]       = sorted(web_cats.items(), key=lambda x: -x[1])[:5]

    # Detalle de antivirus e IPS: subconjuntos pequeños, con índice propio
    cur.execute("""
        SELECT virus, COUNT(*) AS n
        FROM fortinet_threats
        WHERE source = 'antivirus' AND collected_at >= %s AND collected_at < %s
        GROUP BY virus ORDER BY n DESC LIMIT 5
    """, (start, end))
    data["top_virus"] = [(r["virus"] or "desconocido", r["n"]) for r in cur.fetchall()]

    cur.execute("""
        SELECT COUNT(DISTINCT COALESCE(NULLIF(user_email, ''), recipient, dstip)) AS n
        FROM fortinet_threats
        WHERE source = 'antivirus' AND collected_at >= %s AND collected_at < %s
    """, (start, end))
    data["virus_targets"] = cur.fetchone()["n"]

    cur.execute("""
        SELECT payload->>'attack' AS attack, COUNT(*) AS n
        FROM fortinet_threats
        WHERE source = 'ips' AND collected_at >= %s AND collected_at < %s
        GROUP BY 1 ORDER BY n DESC LIMIT 5
    """, (start, end))
    data["top_ips"] = [(r["attack"] or "desconocido", r["n"]) for r in cur.fetchall()]
    return data


def _fortinet_covers(cur, start: datetime) -> bool:
    """La retención de fortinet_threats es corta (60 días): ¿sigue completo el mes que empieza en start?"""
    cur.execute("SELECT MIN(log_date) AS d FROM fortinet_threats")
    first = cur.fetchone()["d"]
    return first is not None and first <= start.date()


def _sentinel_data(cur, start: datetime, end: datetime) -> dict:
    rng = (start, end)
    cur.execute("""
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT agent_name) AS agents,
               COUNT(*) FILTER (WHERE status IS DISTINCT FROM 'resolved') AS unresolved,
               COUNT(*) FILTER (WHERE LOWER(classification) = 'ransomware') AS ransomware,
               COUNT(DISTINCT agent_name) FILTER (WHERE LOWER(classification) = 'ransomware') AS ransomware_agents,
               COUNT(*) FILTER (WHERE LOWER(classification) = 'ransomware'
                                  AND status IS DISTINCT FROM 'resolved') AS ransomware_unresolved
        FROM sentinel_incidents
        WHERE created_at >= %s AND created_at < %s
    """, rng)
    data = {"available": True, **dict(cur.fetchone())}

    cur.execute("""
        SELECT COALESCE(classification, 'General') AS c, COUNT(*) AS n
        FROM sentinel_incidents WHERE created_at >= %s AND created_at < %s
        GROUP BY 1 ORDER BY n DESC
    """, rng)
    data["by_class"] = [(r["c"], r["n"]) for r in cur.fetchall()]

    cur.execute("""
        SELECT threat_name, COUNT(*) AS n, COUNT(DISTINCT agent_name) AS agents
        FROM sentinel_incidents WHERE created_at >= %s AND created_at < %s
        GROUP BY 1 ORDER BY n DESC LIMIT 5
    """, rng)
    data["top_threats"] = [(r["threat_name"] or "desconocido", r["n"], r["agents"]) for r in cur.fetchall()]

    # Software pirata: activadores/cracks detectados como amenaza
    cur.execute("""
        SELECT threat_name, agent_name FROM sentinel_incidents
        WHERE created_at >= %s AND created_at < %s
    """, rng)
    piracy = [r for r in cur.fetchall() if PIRACY_PATTERN.search(r["threat_name"] or "")]
    data["piracy"] = {
        "count":  len(piracy),
        "agents": len({r["agent_name"] for r in piracy}),
        "names":  sorted({r["threat_name"] for r in piracy})[:4],
    }
    return data


def _snyk_scope() -> list[str] | None:
    """Repos en scope según repos_snyk_batch.txt (igual que dashboard/run_snyk_dashboard.py::load_scope_repos)."""
    if not SNYK_SCOPE_BATCH.exists():
        return None
    names = set()
    for line in SNYK_SCOPE_BATCH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(os.path.basename(line.rstrip("/")))
    return sorted(names) or None


def _snyk_data(cur, start: datetime, end: datetime) -> dict:
    scope = _snyk_scope()
    where = """
        f.is_active
        AND NOT EXISTS (SELECT 1 FROM snyk_dismissals sd
                        WHERE sd.repo_name = f.repo_name AND sd.issue_id = f.issue_id
                          AND sd.is_dismissed = TRUE)
        AND (%(scope)s::text[] IS NULL OR f.repo_name = ANY(%(scope)s::text[]))
    """
    params = {"scope": scope, "start": start, "end": end}

    cur.execute(f"""
        SELECT LOWER(f.severity) AS sev,
               COUNT(*) AS active,
               COUNT(*) FILTER (WHERE f.first_seen >= %(start)s AND f.first_seen < %(end)s) AS new
        FROM snyk_findings f WHERE {where}
        GROUP BY 1
    """, params)
    rows = cur.fetchall()
    active = {r["sev"]: r["active"] for r in rows}
    new    = {r["sev"]: r["new"] for r in rows}

    cur.execute(f"""
        SELECT f.repo_name,
               COUNT(*) FILTER (WHERE LOWER(f.severity) = 'critical') AS critical,
               COUNT(*) FILTER (WHERE LOWER(f.severity) = 'high')     AS high
        FROM snyk_findings f
        WHERE {where} AND LOWER(f.severity) IN ('critical', 'high')
        GROUP BY 1 ORDER BY critical DESC, high DESC LIMIT 5
    """, params)
    top_repos = [(r["repo_name"], r["critical"], r["high"]) for r in cur.fetchall()]

    return {"available": True, "active": active, "new": new, "top_repos": top_repos}


def _nmap_data(cur, start: datetime, end: datetime) -> dict:
    # nmap_findings repite el mismo hallazgo en cada escaneo: se cuenta por (equipo, hallazgo)
    cur.execute("""
        WITH f AS (
            SELECT asset_id, title, MAX(severity) AS severity, MIN(first_seen) AS fs,
                   BOOL_OR(status = 'open') AS open
            FROM nmap_findings GROUP BY asset_id, title
        )
        SELECT COUNT(*) FILTER (WHERE fs >= %s AND fs < %s AND severity = 'high')  AS new_high,
               COUNT(*) FILTER (WHERE fs >= %s AND fs < %s)                        AS new_total,
               COUNT(*) FILTER (WHERE open AND severity = 'high')                  AS open_high,
               COUNT(DISTINCT asset_id) FILTER (WHERE open AND severity = 'high')  AS assets_high
        FROM f
    """, (_naive_utc(start), _naive_utc(end)) * 2)
    data = {"available": True, **dict(cur.fetchone())}

    cur.execute("""
        SELECT title, COUNT(DISTINCT asset_id) AS assets
        FROM nmap_findings
        WHERE status = 'open' AND severity = 'high'
        GROUP BY title ORDER BY assets DESC
    """)
    # "Servicio rdp" y "Puerto 3389" son el mismo riesgo: se unifican por descripción
    services: dict[str, int] = {}
    for r in cur.fetchall():
        name = describe_nmap_title(r["title"])
        services[name] = max(services.get(name, 0), r["assets"])
    data["top_services"] = sorted(services.items(), key=lambda x: -x[1])[:5]
    return data


def _cpanel_data(cur, start: datetime, end: datetime) -> dict:
    cur.execute("""
        SELECT COUNT(*) AS events, COUNT(DISTINCT ip) AS ips,
               COALESCE(SUM(attempts), 0) AS attempts,
               COUNT(*) FILTER (WHERE blocked) AS blocked
        FROM cpanel_cphulk_events
        WHERE collected_at >= %s AND collected_at < %s
    """, (start, end))
    return {"available": True, **dict(cur.fetchone())}


def _section(conn, fn, *args, **kwargs) -> dict:
    """Ejecuta una sección aislada: si una fuente falla, el reporte sale sin ella."""
    try:
        with conn.cursor() as cur:
            return fn(cur, *args, **kwargs)
    except Exception as exc:
        conn.rollback()
        logger.warning(f"[exec-report] {fn.__name__} falló: {exc}")
        return {"available": False, "error": str(exc)}


def _kpis(data: dict) -> dict:
    forti, s1, snyk, nmap = data["fortinet"], data["sentinel"], data["snyk"], data["nmap"]
    open_risks = None
    if snyk.get("available") or nmap.get("available"):
        open_risks = (snyk.get("active", {}).get("critical", 0) + snyk.get("active", {}).get("high", 0)
                      + (nmap.get("open_high") or 0))
    return {
        "blocked":    forti.get("blocked") if forti.get("available") else None,
        "incidents":  s1.get("total") if s1.get("available") else None,
        "open_risks": open_risks,
        "pending":    s1.get("unresolved") if s1.get("available") else None,
    }


def _stored_report(cur, period: date) -> dict | None:
    cur.execute("SELECT * FROM executive_reports WHERE period = %s", (period,))
    row = cur.fetchone()
    return dict(row) if row else None


def _previous_kpis(conn, period: date) -> dict:
    """
    KPIs del mes anterior: del reporte guardado si se generó con el mes ya
    cerrado; si no, se recalculan (Fortinet solo si la retención aún lo cubre).
    """
    prev = _prev_month(period)
    _, prev_end = month_bounds(prev)
    with conn.cursor() as cur:
        stored = _stored_report(cur, prev)
    if (stored and stored["status"] == "ready" and stored.get("data")
            and stored["generated_at"] and stored["generated_at"] >= prev_end):
        kpis = dict(stored["data"].get("kpis", {}))
        # open_risks/pending son una foto del momento de generación: solo
        # representan el cierre del mes anterior si se generó poco después
        if stored["generated_at"] > prev_end + timedelta(days=SNAPSHOT_MAX_DAYS):
            kpis["open_risks"] = kpis["pending"] = None
        return kpis

    start, end = month_bounds(prev)
    s1 = _section(conn, _sentinel_data, start, end)
    try:
        with conn.cursor() as cur:
            covered = _fortinet_covers(cur, start)
    except Exception:
        conn.rollback()
        covered = False
    forti = _section(conn, _fortinet_data, start, end, details=False) if covered else {"available": False}
    return {
        "blocked":    forti.get("blocked") if forti.get("available") else None,
        "incidents":  s1.get("total") if s1.get("available") else None,
        "open_risks": None,  # foto del momento: solo existe si el reporte anterior se guardó
        "pending":    None,
    }


def _month_add(d: date, n: int) -> date:
    """Suma (o resta, con n negativo) n meses a un primer día de mes."""
    idx = d.year * 12 + d.month - 1 + n
    return date(idx // 12, idx % 12 + 1, 1)


def _history(conn, period: date, kpis: dict, prev_kpis: dict) -> dict:
    """
    Serie mensual de KPIs para comparar con meses anteriores (máx. 12 meses
    incluyendo el actual). Los datos crudos tienen retención corta (Fortinet
    60 días), así que cada mes sale, en este orden, de:
      1. el mes actual y el anterior: lo que ya se calculó para este reporte
      2. su reporte guardado, si se generó con el mes ya cerrado
      3. SentinelOne en vivo, solo si la retención aún cubre el mes completo
    Lo que no se puede obtener queda en None ("sin datos").
    """
    months = [_month_add(period, -i) for i in range(HISTORY_MONTHS - 1, -1, -1)]
    first  = months[0]
    prev   = _prev_month(period)
    series = {key: [None] * len(months) for key in HISTORY_KEYS}

    with conn.cursor() as cur:
        cur.execute("""
            SELECT period, generated_at, data->'kpis' AS kpis
            FROM executive_reports
            WHERE status = 'ready' AND period >= %s AND period < %s
        """, (first, period))
        stored = {r["period"]: r for r in cur.fetchall()}

    live_incidents: dict[date, int] = {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT MIN(created_at) AS first FROM sentinel_incidents")
            s1_first = cur.fetchone()["first"]
            cur.execute("""
                SELECT date_trunc('month', created_at AT TIME ZONE %(tz)s)::date AS m, COUNT(*) AS n
                FROM sentinel_incidents
                WHERE created_at >= %(start)s AND created_at < %(end)s
                GROUP BY 1
            """, {"tz": TZ_NAME, "start": month_bounds(first)[0], "end": month_bounds(period)[0]})
            counts = {r["m"]: r["n"] for r in cur.fetchall()}
        if s1_first is not None:
            for m in months[:-1]:
                if s1_first <= month_bounds(m)[0]:
                    live_incidents[m] = counts.get(m, 0)
    except Exception as exc:
        conn.rollback()
        logger.warning(f"[exec-report] historial de SentinelOne falló: {exc}")

    for i, m in enumerate(months):
        if m == period:
            values = kpis
        else:
            values = {}
            row = stored.get(m)
            m_end = month_bounds(m)[1]
            if row and row["kpis"] and row["generated_at"] and row["generated_at"] >= m_end:
                values = dict(row["kpis"])
                # Foto del momento: solo vale si se tomó poco después del cierre
                if row["generated_at"] > m_end + timedelta(days=SNAPSHOT_MAX_DAYS):
                    values["open_risks"] = None
            if m == prev:
                values = {**values, **{k: v for k, v in prev_kpis.items() if v is not None}}
            if values.get("incidents") is None and m in live_incidents:
                values["incidents"] = live_incidents[m]
        for key in HISTORY_KEYS:
            series[key][i] = values.get(key)

    return {"months": [m.isoformat() for m in months], "series": series}


def collect_report_data(period: date) -> dict:
    start, end = month_bounds(period)
    now = datetime.now(TZ)
    conn = get_connection()
    try:
        data = {
            "period":       period.isoformat(),
            "label":        period_label(period),
            "partial":      end > now,
            "as_of":        min(now, end).date().isoformat(),
            "generated_at": now.isoformat(),
            "fortinet":     _section(conn, _fortinet_data, start, end),
            "sentinel":     _section(conn, _sentinel_data, start, end),
            "snyk":         _section(conn, _snyk_data, start, end),
            "nmap":         _section(conn, _nmap_data, start, end),
            "cpanel":       _section(conn, _cpanel_data, start, end),
        }
        data["kpis"]      = _kpis(data)
        data["prev_kpis"] = _previous_kpis(conn, period)
        data["history"]   = _history(conn, period, data["kpis"], data["prev_kpis"])
    finally:
        conn.close()

    data["highlights"] = build_highlights(data)
    data["risk_level"] = _risk_level(data["highlights"])
    return data


# =============================================================================
# Las amenazas más importantes (priorizadas)
# =============================================================================

LEVEL_WEIGHT = {"critical": 4, "serious": 3, "warning": 2, "good": 1}


def build_highlights(data: dict) -> list[dict]:
    """
    Convierte las métricas en una lista priorizada de amenazas explicadas en
    lenguaje de negocio. Cada una: nivel, título, cifra, qué pasó y qué hacer.
    """
    out: list[dict] = []
    s1, forti, snyk, nmap, cp = (data["sentinel"], data["fortinet"], data["snyk"],
                                 data["nmap"], data["cpanel"])

    if s1.get("available") and s1.get("ransomware"):
        pending = s1["ransomware_unresolved"]
        out.append({
            "level":  "critical" if pending else "serious",
            "title":  "Intentos de ransomware en computadoras",
            "value":  s1["ransomware"], "unit": "detecciones",
            "detail": (f"El antivirus de las computadoras (SentinelOne) detectó y bloqueó programas de tipo "
                       f"ransomware —que cifran la información para pedir rescate— en "
                       f"{s1['ransomware_agents']} equipo(s)."
                       + (f" {pending} siguen pendientes de revisión." if pending
                          else " Todos quedaron resueltos.")),
            "action": "Revisar los equipos afectados y confirmar con sus usuarios el origen de los archivos.",
        })

    piracy = s1.get("piracy") or {}
    if s1.get("available") and piracy.get("count"):
        out.append({
            "level":  "serious",
            "title":  "Uso de software sin licencia (activadores / cracks)",
            "value":  piracy["count"], "unit": "detecciones",
            "detail": (f"Se encontraron herramientas para activar software sin licencia en {piracy['agents']} "
                       f"equipo(s) ({', '.join(piracy['names'])}). Suelen traer malware oculto y "
                       f"representan además un riesgo legal."),
            "action": "Retirar el software no autorizado y reforzar la política de instalación de programas.",
        })

    if s1.get("available"):
        other = s1["total"] - s1["ransomware"]
        if other > 0:
            pending = s1["unresolved"] - s1["ransomware_unresolved"]
            out.append({
                "level":  "serious" if pending else "warning",
                "title":  "Malware detectado en computadoras",
                "value":  other, "unit": "incidentes",
                "detail": ("Programas maliciosos (virus, troyanos, herramientas de hackeo) detectados y "
                           "contenidos por SentinelOne en las computadoras de la empresa."
                           + (f" {pending} siguen pendientes." if pending else " Todos quedaron resueltos.")),
                "action": "Dar seguimiento a los incidentes pendientes en la consola de SentinelOne.",
            })

    if forti.get("available") and forti["totals"]["antivirus"]:
        top = forti.get("top_virus") or []
        main = f" La amenaza más común: {describe_virus(top[0][0])}." if top else ""
        out.append({
            "level":  "serious",
            "title":  "Archivos maliciosos bloqueados en la red",
            "value":  forti["totals"]["antivirus"], "unit": "archivos",
            "detail": (f"El firewall detuvo archivos con virus —principalmente adjuntos de correo— dirigidos a "
                       f"{_fmt(forti.get('virus_targets'))} destinatario(s).{main}"),
            "action": "Recordar al personal no abrir adjuntos inesperados aunque parezcan de proveedores conocidos.",
        })

    if snyk.get("available"):
        crit = snyk["active"].get("critical", 0)
        high = snyk["active"].get("high", 0)
        if crit or high:
            repos = ", ".join(r[0] for r in snyk["top_repos"][:3])
            out.append({
                "level":  "serious" if crit else "warning",
                "title":  "Vulnerabilidades en aplicaciones propias",
                "value":  crit + high, "unit": "críticas y altas",
                "detail": (f"Las aplicaciones desarrolladas internamente usan componentes con fallas de seguridad "
                           f"conocidas ({crit} críticas, {high} altas). Las más afectadas: {repos}."),
                "action": "Que el equipo de desarrollo actualice las librerías vulnerables, empezando por las críticas.",
            })

    if nmap.get("available") and nmap.get("open_high"):
        services = ", ".join(s[0] for s in nmap["top_services"][:3])
        out.append({
            "level":  "warning",
            "title":  "Servicios sensibles expuestos en la red",
            "value":  nmap["assets_high"], "unit": "equipos",
            "detail": (f"Hay equipos con servicios de alto riesgo accesibles desde la red ({services}). "
                       f"Son puertas de entrada habituales para atacantes."),
            "action": "Cerrar o restringir esos servicios a quien realmente los necesite.",
        })

    if forti.get("available") and forti["totals"]["intrusion"]:
        top = forti.get("top_ips") or []
        main = f" Lo más frecuente: {describe_ips_attack(top[0][0])}." if top else ""
        out.append({
            "level":  "warning",
            "title":  "Intentos de intrusión detenidos",
            "value":  forti["totals"]["intrusion"], "unit": "intentos",
            "detail": f"El sistema de prevención de intrusos del firewall detuvo ataques dirigidos a la red.{main}",
            "action": "Mantener actualizadas las firmas del firewall y los parches de Office/Windows.",
        })

    if forti.get("available") and forti["totals"]["login"]:
        n = forti["totals"]["login"]
        out.append({
            "level":  "serious" if n >= 100 else "warning",
            "title":  "Intentos fallidos de acceso a los firewalls",
            "value":  n, "unit": "intentos",
            "detail": ("Alguien intentó entrar a la administración de los firewalls con credenciales incorrectas. "
                       "Un volumen alto puede indicar que intentan adivinar contraseñas."),
            "action": "Limitar el acceso administrativo a IPs internas y activar doble factor de autenticación.",
        })

    if cp.get("available") and cp.get("events"):
        out.append({
            "level":  "warning",
            "title":  "Ataques de contraseña contra el servidor web",
            "value":  cp["events"], "unit": "eventos",
            "detail": (f"El servidor de hosting registró intentos de adivinar contraseñas desde "
                       f"{_fmt(cp['ips'])} direcciones IP distintas."),
            "action": "Verificar que las cuentas del hosting usen contraseñas robustas.",
        })

    if forti.get("available") and forti["totals"]["web"]:
        cats = ", ".join(c for c, _ in (forti.get("top_web") or [])[:3])
        out.append({
            "level":  "good",
            "title":  "Navegación a sitios no permitidos bloqueada",
            "value":  forti["totals"]["web"], "unit": "accesos",
            "detail": f"El filtro web evitó accesos a sitios riesgosos o fuera de política ({cats}).",
            "action": "Sin acción urgente; el control está funcionando.",
        })

    if forti.get("available") and forti["totals"]["critico"]:
        out.append({
            "level":  "warning",
            "title":  "Eventos críticos de operación en los firewalls",
            "value":  forti["totals"]["critico"], "unit": "eventos",
            "detail": "Los firewalls reportaron eventos críticos de funcionamiento (p. ej. memoria agotada).",
            "action": "Revisar la capacidad de los equipos con el proveedor.",
        })

    # Orden estable por nivel; dentro del mismo nivel se respeta el orden de arriba
    out.sort(key=lambda h: -LEVEL_WEIGHT[h["level"]])
    return out


def _risk_level(highlights: list[dict]) -> str:
    levels = {h["level"] for h in highlights}
    if "critical" in levels:
        return "alto"
    if "serious" in levels:
        return "medio"
    return "bajo"


# =============================================================================
# HTML (compatible con correo: tablas + estilos en línea)
# =============================================================================

# Paleta: un solo azul para magnitudes; colores de estado reservados para nivel de riesgo
C_INK     = "#1f2937"
C_MUTED   = "#6b7280"
C_HAIR    = "#e5e7eb"
C_SURFACE = "#ffffff"
C_BG      = "#f3f4f6"
C_BAR     = "#2a78d6"
C_TRACK   = "#eef2f7"
STATUS = {
    "critical": ("#d03b3b", "#fdecec", "Crítico"),
    "serious":  ("#ec835a", "#fdf1ec", "Importante"),
    "warning":  ("#fab219", "#fef7e6", "Atención"),
    "good":     ("#0ca30c", "#e8f6e8", "Controlado"),
}
RISK = {
    "alto":  ("critical", "ALTO",  "Hay amenazas activas que requieren atención inmediata."),
    "medio": ("serious",  "MEDIO", "Las amenazas fueron contenidas, pero hay riesgos que conviene atender este mes."),
    "bajo":  ("good",     "BAJO",  "No se detectaron amenazas relevantes sin controlar."),
}
SEVERITY_ORDER = [("critical", "Crítica", "#d03b3b"), ("high", "Alta", "#ec835a"),
                  ("medium", "Media", "#fab219"), ("low", "Baja", "#9ca3af")]

FONT = "font-family:'Segoe UI',Arial,Helvetica,sans-serif;"


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _delta(curr, prev, bad_when_up: bool) -> str:
    if curr is None or prev in (None, 0):
        return f'<span style="color:{C_MUTED}">sin comparación con el mes anterior</span>'
    pct = round((curr - prev) * 100 / prev)
    if pct == 0:
        return f'<span style="color:{C_MUTED}">= igual que el mes anterior</span>'
    arrow = "▲" if pct > 0 else "▼"
    color = C_MUTED
    if bad_when_up is not None:
        worse = (pct > 0) == bad_when_up
        color = "#b42318" if worse else "#067647"
    return f'<span style="color:{color};font-weight:600">{arrow} {abs(pct)}%</span> <span style="color:{C_MUTED}">vs. mes anterior</span>'


def _section_title(title: str, subtitle: str = "") -> str:
    sub = f'<div style="{FONT}font-size:13px;color:{C_MUTED};margin-top:4px">{_e(subtitle)}</div>' if subtitle else ""
    return (f'<tr><td style="padding:28px 32px 12px 32px">'
            f'<div style="{FONT}font-size:18px;font-weight:700;color:{C_INK}">{_e(title)}</div>{sub}</td></tr>')


def _hbars(items: list[tuple[str, int]], note: str = "") -> str:
    """Barras horizontales de una sola serie: etiqueta | barra | valor."""
    items = [(l, v) for l, v in items if v]
    if not items:
        return (f'<tr><td style="padding:0 32px 8px 32px;{FONT}font-size:13px;color:{C_MUTED}">'
                f'Sin registros en el periodo.</td></tr>')
    top = max(v for _, v in items)
    rows = []
    for label, value in items:
        pct = max(1, round(value * 100 / top))
        rows.append(f"""
          <tr>
            <td width="38%" style="{FONT}font-size:13px;color:{C_INK};padding:5px 10px 5px 0;vertical-align:middle">{_e(label)}</td>
            <td width="47%" style="padding:5px 0;vertical-align:middle">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
                <td width="{pct}%" height="16" bgcolor="{C_BAR}" style="background:{C_BAR};border-radius:0 4px 4px 0;font-size:0;line-height:0">&nbsp;</td>
                <td width="{100 - pct}%" style="font-size:0;line-height:0">&nbsp;</td>
              </tr></table>
            </td>
            <td width="15%" align="right" style="{FONT}font-size:13px;font-weight:600;color:{C_INK};padding:5px 0 5px 10px;vertical-align:middle;white-space:nowrap">{_fmt(value)}</td>
          </tr>""")
    note_html = (f'<div style="{FONT}font-size:12px;color:{C_MUTED};margin-top:6px">{_e(note)}</div>' if note else "")
    return (f'<tr><td style="padding:0 32px 4px 32px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{"".join(rows)}</table>'
            f'{note_html}</td></tr>')


def _severity_bar(counts: dict) -> str:
    """Barra apilada por severidad + leyenda con cifras (el color nunca va solo)."""
    parts = [(label, counts.get(key, 0), color) for key, label, color in SEVERITY_ORDER]
    total = sum(n for _, n, _ in parts)
    if not total:
        return (f'<tr><td style="padding:0 32px 8px 32px;{FONT}font-size:13px;color:{C_MUTED}">'
                f'Sin vulnerabilidades abiertas.</td></tr>')
    cells = []
    visible = [p for p in parts if p[1]]
    for i, (label, n, color) in enumerate(visible):
        pct = max(2, round(n * 100 / total))
        gap = "border-right:2px solid #ffffff;" if i < len(visible) - 1 else ""
        cells.append(f'<td width="{pct}%" height="22" bgcolor="{color}" style="background:{color};{gap}font-size:0;line-height:0">&nbsp;</td>')
    legend = "".join(
        f'<td style="{FONT}font-size:13px;color:{C_INK};padding:8px 16px 0 0;white-space:nowrap">'
        f'<span style="display:inline-block;width:10px;height:10px;background:{color};border-radius:2px;margin-right:6px"></span>'
        f'{label}: <b>{_fmt(n)}</b></td>'
        for label, n, color in parts
    )
    return (f'<tr><td style="padding:0 32px 4px 32px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-radius:4px;overflow:hidden"><tr>{"".join(cells)}</tr></table>'
            f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{legend}</tr></table>'
            f'</td></tr>')


C_BAR_CURRENT = "#123f7a"   # mes del reporte: mismo tono, más oscuro
TREND_HEIGHT  = 110         # alto máximo de las columnas, en px


def _short(n: int | float) -> str:
    """Cifra compacta para etiquetas de columnas: 807 mil, 1.2 M."""
    n = int(n)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}".rstrip("0").rstrip(".") + " M"
    if n >= 10_000:
        return f"{round(n / 1000)} mil"
    return _fmt(n)


def _trend_chart(months: list[date], values: list, partial: bool, bad_when_up: bool,
                 missing_note: str) -> str:
    """
    Columnas verticales por mes (tablas, compatibles con correo). El mes del
    reporte va más oscuro y en negritas; los meses sin datos dicen "s/d".
    Los meses iniciales sin datos se omiten (el historial se va llenando) y el
    ancho de columna es fijo, para que todas las gráficas se vean iguales.
    """
    slots = len(months)
    skip = next(i for i, v in enumerate(values) if v is not None)
    months, values = months[skip:], values[skip:]
    known = [v for v in values if v is not None]
    top = max(known) or 1
    last = len(values) - 1

    bars, labels = [], []
    for i, (m, v) in enumerate(zip(months, values)):
        current = i == last
        weight = "700" if current else "400"
        if v is None:
            bar = (f'<div style="{FONT}font-size:10px;color:{C_MUTED};padding-bottom:2px">s/d</div>')
        else:
            h = max(3, round(v * TREND_HEIGHT / top)) if v else 1
            color = C_BAR_CURRENT if current else C_BAR
            bar = (f'<div style="{FONT}font-size:10px;font-weight:{weight};color:{C_INK};padding-bottom:3px;white-space:nowrap">{_short(v)}</div>'
                   f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
                   f'<td height="{h}" bgcolor="{color}" style="height:{h}px;background:{color};border-radius:3px 3px 0 0;font-size:0;line-height:0">&nbsp;</td>'
                   f'</tr></table>')
        bars.append(f'<td width="{100 // slots}%" height="{TREND_HEIGHT + 22}" valign="bottom" align="center" '
                    f'style="height:{TREND_HEIGHT + 22}px;padding:0 3px;vertical-align:bottom">{bar}</td>')
        mark = "*" if current and partial else ""
        labels.append(f'<td align="center" style="{FONT}font-size:10px;font-weight:{weight};color:{C_INK if current else C_MUTED};'
                      f'padding:5px 0 0 0;border-top:1px solid {C_HAIR};white-space:nowrap">'
                      f'{MONTHS_ES[m.month - 1][:3]}{mark}<br/>{m.year % 100:02d}</td>')

    # Lectura en una línea: el mes contra el promedio de los meses anteriores con datos
    prev_known = [v for v in values[:-1] if v is not None]
    curr = values[-1]
    notes = []
    if prev_known and curr is not None:
        avg = sum(prev_known) / len(prev_known)
        months_txt = "mes anterior" if len(prev_known) == 1 else f"{len(prev_known)} meses anteriores"
        line = f"Promedio de los {months_txt}: <b>{_fmt(round(avg))}</b>." if len(prev_known) > 1 \
            else f"Valor del {months_txt}: <b>{_fmt(round(avg))}</b>."
        if avg and not partial:
            pct = round((curr - avg) * 100 / avg)
            if pct == 0:
                line += " Este mes quedó en el promedio."
            else:
                if bad_when_up is None:     # más bloqueos no es ni bueno ni malo
                    color = C_INK
                else:
                    color = "#b42318" if (pct > 0) == bad_when_up else "#067647"
                word = "por encima" if pct > 0 else "por debajo"
                line += (f' Este mes quedó <span style="color:{color};font-weight:600">'
                         f'{"▲" if pct > 0 else "▼"} {abs(pct)}% {word}</span>.')
        notes.append(line)
    if partial:
        notes.append("* Mes en curso: cifra parcial, no comparable todavía.")
    if skip:
        m0 = months[0]
        notes.append(f"Historial disponible desde {MONTHS_ES[m0.month - 1]} {m0.year}; "
                     f"se irá completando mes a mes hasta cubrir {slots} meses.")
    if any(v is None for v in values):
        notes.append(f"s/d: sin datos de ese mes ({missing_note}).")
    notes_html = "".join(f'<div style="{FONT}font-size:12px;color:{C_MUTED};margin-top:6px;line-height:1.4">{n}</div>'
                         for n in notes)
    filler = (f'<td width="{100 - (100 // slots) * len(values)}%" style="font-size:0;line-height:0">&nbsp;</td>'
              if len(values) < slots else "")

    return (f'<tr><td style="padding:0 32px 4px 32px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr>{"".join(bars)}{filler}</tr><tr>{"".join(labels)}{filler}</tr></table>'
            f'{notes_html}</td></tr>')


def _history_section(data: dict) -> list[str]:
    """Gráficas de comparación con meses anteriores. Solo las series con ≥2 meses con datos."""
    hist = data.get("history")   # los reportes guardados antes de esta función no la traen
    if not hist:
        return []
    months = [date.fromisoformat(m) for m in hist["months"]]
    charts = [
        ("blocked",    "Amenazas bloqueadas en la red", "Registros de los firewalls FortiGate por mes", None,
         "el detalle de los firewalls se conserva 60 días; los meses anteriores salen de los reportes ya generados"),
        ("incidents",  "Incidentes en computadoras", "Detectados por SentinelOne por mes", True,
         "no hay reporte guardado y el detalle ya no cubre el mes completo"),
        ("open_risks", "Vulnerabilidades críticas y altas abiertas",
         "Aplicaciones propias y servicios expuestos en la red, al cierre de cada mes", True,
         "es una foto al cierre del mes: solo existe si el reporte se generó en los primeros "
         f"{SNAPSHOT_MAX_DAYS} días del mes siguiente"),
    ]
    out: list[str] = []
    for key, title, subtitle, bad_when_up, missing_note in charts:
        values = hist["series"].get(key) or []
        if sum(v is not None for v in values) < 2:
            continue
        out.append(_section_title(title, subtitle))
        out.append(_trend_chart(months, values, data["partial"], bad_when_up, missing_note))
    if out:
        n = len(months)
        out.insert(0, f'<tr><td style="padding:28px 32px 0 32px"><div style="{FONT}font-size:12px;color:{C_MUTED};'
                      f'text-transform:uppercase;letter-spacing:.08em">Comparación con meses anteriores · últimos {n} meses</div></td></tr>')
    return out


def _kpi_tile(value, label: str, delta_html: str) -> str:
    return (f'<td width="50%" valign="top" style="padding:6px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="border:1px solid {C_HAIR};border-radius:10px"><tr><td style="padding:16px 18px">'
            f'<div style="{FONT}font-size:30px;font-weight:700;color:{C_INK};line-height:1.1">{_fmt(value)}</div>'
            f'<div style="{FONT}font-size:13px;color:{C_INK};margin-top:6px">{_e(label)}</div>'
            f'<div style="{FONT}font-size:12px;margin-top:6px">{delta_html}</div>'
            f'</td></tr></table></td>')


def _highlight_card(i: int, h: dict) -> str:
    color, bg, label = STATUS[h["level"]]
    return f"""
      <tr><td style="padding:0 32px 12px 32px">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
               style="border:1px solid {C_HAIR};border-left:4px solid {color};border-radius:8px">
          <tr><td style="padding:14px 18px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
              <td style="{FONT}font-size:15px;font-weight:700;color:{C_INK}">{i}. {_e(h['title'])}</td>
              <td align="right" style="white-space:nowrap">
                <span style="{FONT}display:inline-block;background:{bg};color:{C_INK};border:1px solid {color};border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600">● {label}</span>
              </td>
            </tr></table>
            <div style="{FONT}margin-top:6px"><span style="font-size:22px;font-weight:700;color:{C_INK}">{_fmt(h['value'])}</span>
              <span style="font-size:13px;color:{C_MUTED}">{_e(h['unit'])}</span></div>
            <div style="{FONT}font-size:13px;color:{C_INK};line-height:1.5;margin-top:6px">{_e(h['detail'])}</div>
            <div style="{FONT}font-size:13px;color:{C_INK};line-height:1.5;margin-top:8px"><b>Qué se recomienda:</b> {_e(h['action'])}</div>
          </td></tr>
        </table>
      </td></tr>"""


def _summary_sentence(data: dict) -> str:
    k = data["kpis"]
    parts = []
    if k["blocked"] is not None:
        parts.append(f"los sistemas de seguridad bloquearon {_fmt(k['blocked'])} amenazas en la red")
    if k["incidents"] is not None:
        parts.append(f"se atendieron {_fmt(k['incidents'])} incidentes en computadoras")
    if not parts:
        return ""
    text = "Durante el periodo " + " y ".join(parts) + "."
    if k["pending"]:
        text += f" Quedan {_fmt(k['pending'])} incidentes pendientes de revisión."
    return text


def build_report_html(data: dict) -> str:
    period = date.fromisoformat(data["period"])
    title_period = data["label"]
    if data["partial"]:
        as_of = date.fromisoformat(data["as_of"])
        title_period += f" (parcial, al {as_of.day} de {MONTHS_ES[as_of.month - 1]})"

    risk_key, risk_word, risk_text = RISK[data["risk_level"]]
    risk_color, risk_bg, _ = STATUS[risk_key]
    k, pk = data["kpis"], data.get("prev_kpis") or {}
    forti, s1, snyk = data["fortinet"], data["sentinel"], data["snyk"]

    body: list[str] = []

    # Nivel de riesgo + resumen
    body.append(f"""
      <tr><td style="padding:24px 32px 4px 32px">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:{risk_bg};border-left:5px solid {risk_color};border-radius:8px">
          <tr><td style="padding:16px 20px">
            <div style="{FONT}font-size:12px;color:{C_MUTED};text-transform:uppercase;letter-spacing:.08em">Nivel de riesgo del mes</div>
            <div style="{FONT}font-size:24px;font-weight:800;color:{C_INK};margin-top:2px">● {risk_word}</div>
            <div style="{FONT}font-size:14px;color:{C_INK};line-height:1.5;margin-top:6px">{_e(risk_text)} {_e(_summary_sentence(data))}</div>
          </td></tr>
        </table>
      </td></tr>""")

    # KPIs
    body.append(_section_title("El mes en cifras"))
    body.append(f"""
      <tr><td style="padding:0 26px">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>{_kpi_tile(k['blocked'], 'Amenazas bloqueadas en la red', _delta(k['blocked'], pk.get('blocked'), None))}
              {_kpi_tile(k['incidents'], 'Incidentes en computadoras', _delta(k['incidents'], pk.get('incidents'), True))}</tr>
          <tr>{_kpi_tile(k['open_risks'], 'Vulnerabilidades críticas y altas abiertas', _delta(k['open_risks'], pk.get('open_risks'), True))}
              {_kpi_tile(k['pending'], 'Incidentes pendientes de atender', f'<span style="color:{C_MUTED}">al cierre del reporte</span>')}</tr>
        </table>
      </td></tr>""")

    # Tendencia: comparación con los meses anteriores (máx. 12)
    body.extend(_history_section(data))

    # Amenazas más importantes
    top = data["highlights"][:5]
    body.append(_section_title("Las amenazas más importantes del mes",
                               "Ordenadas por nivel de riesgo para el negocio"))
    if top:
        body.extend(_highlight_card(i, h) for i, h in enumerate(top, 1))
    else:
        body.append(f'<tr><td style="padding:0 32px;{FONT}font-size:13px;color:{C_MUTED}">No se registraron amenazas relevantes.</td></tr>')

    # Gráficas
    if forti.get("available"):
        months_short = MONTHS_ES[period.month - 1][:3]
        body.append(_section_title("Amenazas bloqueadas por semana",
                                   "Conexiones, sitios, archivos con virus e intrusiones detenidas por los firewalls"))
        body.append(_hbars([(f"Del {w['label'].replace('–', ' al ')} {months_short}", w["total"]) for w in forti["weeks"]]))

        body.append(_section_title("¿Qué tipo de amenazas enfrentamos?", "Registros de los firewalls en el mes"))
        body.append(_hbars(sorted(((FORTI_CATEGORIES[c][0], n) for c, n in forti["totals"].items()),
                                  key=lambda x: -x[1])))

        if forti.get("top_virus"):
            # Variantes de la misma familia (p.ej. dos firmas de FormBook) se suman
            families: dict[str, int] = {}
            for v, n in forti["top_virus"]:
                desc = describe_virus(v)
                desc = desc[:1].upper() + desc[1:]
                families[desc] = families.get(desc, 0) + n
            body.append(_section_title("Virus más frecuentes bloqueados", "Archivos detenidos por el antivirus del firewall"))
            body.append(_hbars(sorted(families.items(), key=lambda x: -x[1])))

    if s1.get("available") and s1.get("total"):
        body.append(_section_title("Incidentes en computadoras por tipo", "Detectados por SentinelOne"))
        body.append(_hbars([(SENTINEL_CLASSES.get((c or "").lower(), c), n) for c, n in s1["by_class"]]))

    if snyk.get("available"):
        new_ch = snyk["new"].get("critical", 0) + snyk["new"].get("high", 0)
        body.append(_section_title("Vulnerabilidades abiertas en aplicaciones propias",
                                   f"Por nivel de riesgo · {_fmt(new_ch)} críticas/altas nuevas este mes"))
        body.append(_severity_bar(snyk["active"]))
        if snyk["top_repos"]:
            body.append(_hbars(sorted(((r, c + h) for r, c, h in snyk["top_repos"]), key=lambda x: -x[1]),
                               note="Aplicaciones con más vulnerabilidades críticas y altas"))

    # Recomendaciones
    actions = []
    for h in data["highlights"]:
        if h["level"] in ("critical", "serious") and h["action"] not in actions:
            actions.append(h["action"])
    if actions:
        body.append(_section_title("Recomendaciones para el próximo mes"))
        items = "".join(f'<li style="margin-bottom:6px">{_e(a)}</li>' for a in actions[:4])
        body.append(f'<tr><td style="padding:0 32px 0 32px;{FONT}font-size:14px;color:{C_INK};line-height:1.5">'
                    f'<ol style="margin:0;padding-left:20px">{items}</ol></td></tr>')

    # Glosario
    glossary = [
        ("Firewall", "equipo que controla qué entra y sale de la red de la empresa."),
        ("Ransomware", "programa que cifra la información y pide un rescate para devolverla."),
        ("Vulnerabilidad", "falla en un programa que un atacante podría aprovechar."),
        ("Intrusión", "intento de entrar a un sistema sin autorización."),
    ]
    gl = "".join(f'<div style="margin-bottom:4px"><b>{_e(t)}:</b> {_e(d)}</div>' for t, d in glossary)
    body.append(_section_title("Glosario"))
    body.append(f'<tr><td style="padding:0 32px;{FONT}font-size:12px;color:{C_MUTED};line-height:1.5">{gl}</td></tr>')

    generated = datetime.fromisoformat(data["generated_at"]).strftime("%d/%m/%Y %H:%M")
    missing = [name for key, name in (("fortinet", "FortiGate"), ("sentinel", "SentinelOne"),
                                      ("snyk", "Snyk"), ("nmap", "Nmap"))
               if not data[key].get("available")]
    missing_html = (f"<br/>Fuentes no disponibles al generar: {_e(', '.join(missing))}." if missing else "")

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Reporte ejecutivo de seguridad — {_e(data['label'])}</title>
<style>@media print {{ body {{ background:#ffffff !important; }} }}</style>
</head>
<body style="margin:0;padding:0;background:{C_BG}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{C_BG}" style="background:{C_BG}">
  <tr><td align="center" style="padding:24px 12px">
    <table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" bgcolor="{C_SURFACE}"
           style="width:100%;max-width:680px;background:{C_SURFACE};border-radius:12px;overflow:hidden">
      <tr><td bgcolor="#0f172a" style="background:#0f172a;padding:28px 32px">
        <div style="{FONT}font-size:12px;color:#93c5fd;letter-spacing:.12em;text-transform:uppercase">Leviathan SOC · Reporte ejecutivo</div>
        <div style="{FONT}font-size:26px;font-weight:700;color:#ffffff;margin-top:6px">Resumen de seguridad</div>
        <div style="{FONT}font-size:15px;color:#cbd5e1;margin-top:4px">{_e(title_period)}</div>
      </td></tr>
      {''.join(body)}
      <tr><td style="padding:28px 32px 28px 32px">
        <div style="border-top:1px solid {C_HAIR};padding-top:14px;{FONT}font-size:11px;color:{C_MUTED};line-height:1.5">
          Generado automáticamente por la plataforma SOC el {generated}. Fuentes: firewalls FortiGate,
          antivirus SentinelOne, análisis de código Snyk y escaneo de red Nmap.{missing_html}
        </div>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""


# =============================================================================
# Persistencia, envío y job automático
# =============================================================================

def start_generation(period: date) -> tuple[int, bool]:
    """
    Marca el periodo como 'generating'. Devuelve (report_id, iniciado). Si ya
    hay una generación reciente en curso no la duplica (iniciado=False).
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"""
                INSERT INTO executive_reports (period, status, started_at)
                VALUES (%s, 'generating', NOW())
                ON CONFLICT (period) DO UPDATE
                    SET status = 'generating', started_at = NOW(), error = NULL
                    WHERE executive_reports.status <> 'generating'
                       OR executive_reports.started_at < NOW() - INTERVAL '{STALE_GENERATION_MINUTES} minutes'
                RETURNING id
            """, (period,))
            row = cur.fetchone()
            if row:
                conn.commit()
                return row["id"], True
            cur.execute("SELECT id FROM executive_reports WHERE period = %s", (period,))
            return cur.fetchone()["id"], False
    finally:
        conn.close()


def build_and_store(report_id: int, period: date) -> dict:
    """Recolecta, arma el HTML y lo guarda. No lanza: deja status=failed con el error."""
    try:
        data = collect_report_data(period)
        body = build_report_html(data)
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE executive_reports
                    SET status = 'ready', data = %s, html = %s, error = NULL, generated_at = NOW()
                    WHERE id = %s
                """, (json.dumps(data, default=str), body, report_id))
            conn.commit()
        finally:
            conn.close()
        logger.info(f"[exec-report] Reporte {period:%Y-%m} generado (id={report_id})")
        return {"ok": True, "id": report_id}
    except Exception as exc:
        logger.error(f"[exec-report] Error generando {period:%Y-%m}: {exc}")
        try:
            conn = get_connection()
            with conn.cursor() as cur:
                cur.execute("UPDATE executive_reports SET status = 'failed', error = %s WHERE id = %s",
                            (str(exc)[:2000], report_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {"ok": False, "id": report_id, "error": str(exc)}


def _log_send(report_id: int, recipients: list[str], trigger: str, ok: bool, error: str | None) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO executive_report_sends (report_id, recipients, trigger, status, error)
                VALUES (%s, %s, %s, %s, %s)
            """, (report_id, recipients, trigger, "sent" if ok else "failed", error))
        conn.commit()
    finally:
        conn.close()


def send_report(report_id: int, recipients: list[str], trigger: str = "manual") -> dict:
    from app.alerts.engine import send_email

    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        return {"ok": False, "error": "Sin destinatarios"}

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT period, status, html FROM executive_reports WHERE id = %s", (report_id,))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return {"ok": False, "error": "Reporte no encontrado"}
    if row["status"] != "ready" or not row["html"]:
        return {"ok": False, "error": "El reporte aún no está listo"}

    subject = f"[SOC] Reporte ejecutivo de seguridad — {period_label(row['period'])}"
    ok = send_email(recipients, subject, row["html"])
    error = None if ok else "Error enviando el correo — revisa la configuración SMTP y los logs"
    _log_send(report_id, recipients, trigger, ok, error)
    return {"ok": ok, "error": error}


def get_config() -> dict:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM executive_report_config WHERE id = 1")
            row = cur.fetchone()
    finally:
        conn.close()
    return dict(row) if row else {"enabled": False, "recipients": [], "send_day": 1, "send_hour": 8}


def run_monthly_job() -> dict:
    """
    Envío automático: a partir del día/hora configurados, genera el reporte del
    mes anterior y lo envía una sola vez. Se llama cada hora, así que si el
    scheduler estuvo caído a la hora exacta, el envío se recupera después.
    """
    cfg = get_config()
    if not cfg.get("enabled") or not cfg.get("recipients"):
        return {"ok": True, "skipped": "desactivado o sin destinatarios"}

    now = datetime.now(TZ)
    if (now.day, now.hour) < (cfg["send_day"], cfg["send_hour"]):
        return {"ok": True, "skipped": "aún no es la fecha de envío"}

    period = parse_period(None)
    _, period_end = month_bounds(period)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) FILTER (WHERE s.status = 'sent') AS sent, COUNT(*) AS attempts
                FROM executive_report_sends s JOIN executive_reports r ON r.id = s.report_id
                WHERE r.period = %s AND s.trigger = 'auto'
            """, (period,))
            sends = cur.fetchone()
            stored = _stored_report(cur, period)
    finally:
        conn.close()

    if sends["sent"]:
        return {"ok": True, "skipped": "ya enviado"}
    if sends["attempts"] >= MAX_AUTO_ATTEMPTS:
        return {"ok": False, "error": f"se agotaron los {MAX_AUTO_ATTEMPTS} intentos automáticos"}

    # Reusar el reporte si ya se generó con el mes cerrado; si no, generarlo
    if stored and stored["status"] == "ready" and stored["generated_at"] and stored["generated_at"] >= period_end:
        report_id = stored["id"]
    else:
        report_id, started = start_generation(period)
        if not started:
            return {"ok": True, "skipped": "generación en curso desde el panel"}
        result = build_and_store(report_id, period)
        if not result["ok"]:
            _log_send(report_id, list(cfg["recipients"]), "auto", False, f"Generación fallida: {result['error']}")
            return result

    return send_report(report_id, list(cfg["recipients"]), trigger="auto")
