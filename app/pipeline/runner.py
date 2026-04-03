from __future__ import annotations

from app.modules.nmap.pipeline_nmap import run_nmap_pipeline

# Sentinel
try:
    from app.modules.sentinel.service import run_sentinel_pipeline
except Exception:
    def run_sentinel_pipeline(**kwargs):
        return {
            "ok": False,
            "message": "Sentinel pipeline no configurado en runner.py",
            "kwargs": kwargs,
        }

# Snyk
try:
    from app.modules.snyk.service import run_snyk_pipeline
except Exception:
    def run_snyk_pipeline(**kwargs):
        return {
            "ok": False,
            "message": "Snyk pipeline no configurado en runner.py",
            "kwargs": kwargs,
        }

# Fortinet
try:
    from app.modules.fortinet.service import run_fortinet_pipeline
except Exception:
    def run_fortinet_pipeline(**kwargs):
        return {
            "ok": False,
            "message": "Fortinet pipeline no configurado en runner.py",
            "kwargs": kwargs,
        }

PIPELINES = {
    "nmap": run_nmap_pipeline,
    "sentinel": run_sentinel_pipeline,
    "snyk": run_snyk_pipeline,
    "fortinet": run_fortinet_pipeline,
}

def run_module(name: str, **kwargs):
    if name not in PIPELINES:
        raise ValueError(f"Pipeline no registrado: {name}")

    return PIPELINES[name](**kwargs)

def run_pipeline(name: str, **kwargs):
    return run_module(name, **kwargs)