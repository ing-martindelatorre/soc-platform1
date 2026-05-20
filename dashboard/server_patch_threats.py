"""
INSTRUCCIONES DE APLICACIÓN:
==============================
En dashboard/server.py reemplaza la función build_fortinet_threats_data()
completa por esta versión. También reemplaza la función refresh_fortinet_threats().

CAMBIOS:
- build_fortinet_threats_data() ahora acepta parámetro hours (24 o 168 para 7 días)
- refresh_fortinet_threats() genera DOS archivos JSON:
    - fortinet_threats_data.json      (últimas 24 horas)
    - fortinet_threats_data_7d.json   (últimos 7 días)
- Se agrega tarea de limpieza automática de registros > 1 año
"""

# ─── REEMPLAZAR ESTA FUNCIÓN ──────────────────────────────────────────────────

def build_fortinet_threats_data(hours: int = 24) -> dict:
    """
    Lee datos de amenazas de fortinet_threats filtrando por período.
    hours=24  → últimas 24 horas
    hours=168 → últimos 7 días
    """
    with db_connect() as conn:
        with conn.cursor() as cur:

            interval = f"{hours} hours"

            # Summary con filtro de tiempo
            cur.execute(f"""
                SELECT source, classification, COUNT(*) AS n
                FROM fortinet_threats
                WHERE collected_at >= NOW() - INTERVAL '{interval}'
                GROUP BY source, classification
            """)
            rows = cur.fetchall()

            counts: dict = {}
            for r in rows:
                src = r["source"]
                cls = r["classification"]
                n   = int(r["n"])
                if src not in counts:
                    counts[src] = {}
                counts[src][cls] = n

            # Tráfico
            cur.execute(f"""
                SELECT srcip, srcname, dstip, dstport, dstcountry,
                       action, app, apprisk, service, policyname,
                       sentbyte, rcvdbyte, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='traffic'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                ORDER BY collected_at DESC LIMIT 200
            """)
            traffic_records = [dict(r) for r in cur.fetchall()]

            # Eventos
            cur.execute(f"""
                SELECT logdesc, level, action, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='event'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                ORDER BY collected_at DESC LIMIT 200
            """)
            event_records = [dict(r) for r in cur.fetchall()]

            # Webfilter
            cur.execute(f"""
                SELECT srcip, dstip, hostname, url, catdesc, action, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='webfilter'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                ORDER BY collected_at DESC LIMIT 200
            """)
            webfilter_records = [dict(r) for r in cur.fetchall()]

            # IPS
            cur.execute(f"""
                SELECT srcip, dstip, action, classification, payload,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='ips'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                ORDER BY collected_at DESC LIMIT 100
            """)
            ips_records = [dict(r) for r in cur.fetchall()]

            # VPN
            cur.execute(f"""
                SELECT srcip, action, level, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='vpn'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                ORDER BY collected_at DESC LIMIT 100
            """)
            vpn_records = [dict(r) for r in cur.fetchall()]

            # Tráfico sospechoso agrupado por hora (para gráfica de tendencia)
            cur.execute(f"""
                SELECT
                    DATE_TRUNC('hour', collected_at) AS hora,
                    COUNT(*) AS total,
                    SUM(CASE WHEN classification = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
                    SUM(CASE WHEN classification = 'blocked'    THEN 1 ELSE 0 END) AS blocked
                FROM fortinet_threats
                WHERE source = 'traffic'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                GROUP BY 1
                ORDER BY 1
            """)
            traffic_over_time = [
                {
                    "hora":      str(r["hora"]),
                    "total":     int(r["total"]),
                    "suspicious": int(r["suspicious"]),
                    "blocked":   int(r["blocked"]),
                }
                for r in cur.fetchall()
            ]

    def top_counter(records, key, limit=8):
        c = Counter(str(r.get(key) or '') for r in records if r.get(key))
        return [{"value": k, "count": v} for k, v in c.most_common(limit)]

    tc = counts.get("traffic", {})
    ec = counts.get("event", {})
    wc = counts.get("webfilter", {})

    return {
        "generated_at": now_str(),
        "period_hours": hours,
        "period_label": "Últimas 24 horas" if hours == 24 else "Últimos 7 días",
        "summary": {
            "total_traffic":      sum(tc.values()),
            "suspicious_traffic": tc.get("suspicious", 0),
            "blocked_traffic":    tc.get("blocked", 0),
            "total_events":       sum(ec.values()),
            "login_failures":     ec.get("login_failure", 0),
            "critical_events":    ec.get("critical", 0),
            "total_webfilter":    sum(wc.values()),
            "blocked_webfilter":  wc.get("blocked", 0),
            "total_ips":          sum(counts.get("ips", {}).values()),
            "total_vpn":          sum(counts.get("vpn", {}).values()),
        },
        "traffic": {
            "records": traffic_records,
            "over_time": traffic_over_time,
            "summary": {
                "total":      sum(tc.values()),
                "suspicious": tc.get("suspicious", 0),
                "blocked":    tc.get("blocked", 0),
                "normal":     tc.get("normal", 0),
                "top_dstcountry": top_counter(traffic_records, "dstcountry"),
                "top_app":        top_counter(traffic_records, "app"),
                "top_srcip":      top_counter(traffic_records, "srcip"),
                "top_action":     top_counter(traffic_records, "action", 5),
            },
        },
        "events": {
            "records":        event_records,
            "login_failures": [r for r in event_records if r["classification"] == "login_failure"],
            "critical":       [r for r in event_records if r["classification"] == "critical"],
            "summary": {
                "total":          sum(ec.values()),
                "login_failures": ec.get("login_failure", 0),
                "critical":       ec.get("critical", 0),
                "top_logdesc":    top_counter(event_records, "logdesc"),
            },
        },
        "webfilter": {
            "records": webfilter_records,
            "summary": {
                "total":      sum(wc.values()),
                "blocked":    wc.get("blocked", 0),
                "suspicious": wc.get("suspicious", 0),
                "allowed":    wc.get("allowed", 0),
                "top_catdesc":  top_counter(webfilter_records, "catdesc"),
                "top_hostname": top_counter(webfilter_records, "hostname"),
            },
        },
        "ips": {
            "records": ips_records,
            "summary": {"total": len(ips_records)},
        },
        "vpn": {
            "records": vpn_records,
            "summary": {"total": len(vpn_records)},
        },
    }


# ─── REEMPLAZAR ESTA FUNCIÓN ──────────────────────────────────────────────────

def refresh_fortinet_threats():
    while True:
        try:
            # Generar JSON de 24 horas
            data_24h = build_fortinet_threats_data(hours=24)
            (BASE_DIR / "fortinet_threats_data.json").write_text(
                json.dumps(data_24h, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )

            # Generar JSON de 7 días
            data_7d = build_fortinet_threats_data(hours=168)
            (BASE_DIR / "fortinet_threats_data_7d.json").write_text(
                json.dumps(data_7d, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )

            total = data_24h["summary"]["total_traffic"]
            susp  = data_24h["summary"]["suspicious_traffic"]
            print(f"[fortinet-threats] OK — 24h: traffic={total}, suspicious={susp} | {now_str()}")

        except Exception as e:
            print(f"[fortinet-threats] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet_threats"])


# ─── AGREGAR ESTA FUNCIÓN (nueva) ─────────────────────────────────────────────
# Llámala desde main() como un thread daemon:
# threading.Thread(target=cleanup_fortinet_threats, daemon=True, name="forti-cleanup")

def cleanup_fortinet_threats():
    """Borra registros de fortinet_threats con más de 1 año. Corre cada 24 horas."""
    while True:
        try:
            with db_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        DELETE FROM fortinet_threats
                        WHERE collected_at < NOW() - INTERVAL '1 year'
                    """)
                    deleted = cur.rowcount
                conn.commit()
            if deleted > 0:
                print(f"[forti-cleanup] Eliminados {deleted} registros > 1 año | {now_str()}")
        except Exception as e:
            print(f"[forti-cleanup] ERROR: {e}")
        time.sleep(86400)  # 24 horas
