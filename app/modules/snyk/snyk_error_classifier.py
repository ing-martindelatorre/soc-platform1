from __future__ import annotations


def normalize_text(*parts: str | None) -> str:
    return "\n".join([p or "" for p in parts]).lower()


def classify_snyk_result(exit_code: int, stdout: str = "", stderr: str = "") -> str:
    """
    Clasifica el resultado del CLI de Snyk en estados útiles para el pipeline.

    Estados:
      - success_no_issues
      - success_with_issues
      - no_supported_project
      - failed_quota
      - failed_rate_limit
      - failed_auth
      - failed_network
      - failed_cli_error
    """
    text = normalize_text(stdout, stderr)

    if exit_code == 0:
        return "success_no_issues"

    if exit_code == 1:
        # En Snyk test esto normalmente significa findings encontrados
        return "success_with_issues"

    if exit_code == 3:
        return "no_supported_project"

    auth_patterns = [
        "authentication failed",
        "unauthorized",
        "forbidden",
        "invalid token",
        "token is invalid",
        "missing api token",
        "snyk token",
        "401",
        "403",
    ]
    if any(p in text for p in auth_patterns):
        return "failed_auth"

    rate_limit_patterns = [
        "429",
        "too many requests",
        "rate limit",
        "rate-limit",
    ]
    if any(p in text for p in rate_limit_patterns):
        return "failed_rate_limit"

    quota_patterns = [
        "quota",
        "usage limit",
        "test limit",
        "limit reached",
        "monthly limit",
        "you have reached",
        "not enough tests",
    ]
    if any(p in text for p in quota_patterns):
        return "failed_quota"

    network_patterns = [
        "econnreset",
        "etimedout",
        "timed out",
        "network",
        "socket hang up",
        "getaddrinfo",
        "unable to connect",
        "connection refused",
    ]
    if any(p in text for p in network_patterns):
        return "failed_network"

    return "failed_cli_error"


def is_valid_scan_status(status: str) -> bool:
    return status in {"success_no_issues", "success_with_issues"}


def is_blocking_status(status: str) -> bool:
    return status in {"failed_quota", "failed_rate_limit", "failed_auth"}


def build_error_signature(stdout: str = "", stderr: str = "", max_len: int = 500) -> str:
    text = normalize_text(stdout, stderr).strip()
    if not text:
        return ""
    return text[:max_len]