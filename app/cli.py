from __future__ import annotations

import argparse

from app.core.logging import setup_logging
from app.pipeline.runner import run_module


def build_parser():
    parser = argparse.ArgumentParser(description="SOC Security Platform")

    parser.add_argument(
        "module",
        choices=["sentinel", "snyk", "nmap", "fortinet", "cpanel"],
        help="module to run"
    )

    parser.add_argument("--mode", choices=["config", "logs", "stats", "security", "accounts"], default="config")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--csv-path")
    parser.add_argument("--log-path")
    parser.add_argument("--endpoint", default="/api/v2/log/disk/traffic/forward/system")
    parser.add_argument("--date-from")
    parser.add_argument("--date-to")

    return parser



def main():
    logger = setup_logging()
    parser = build_parser()
    args = parser.parse_args()

    kwargs = {
        "mode": args.mode,
        "limit": args.limit,
        "csv_path": args.csv_path,
        "log_path": args.log_path,
        "endpoint": args.endpoint,
        "date_from": args.date_from,
        "date_to": args.date_to,
    }

    logger.info(f"Running module: {args.module}")
    result = run_module(args.module, **kwargs)
    logger.info(f"Result: {result}")


if __name__ == "__main__":
    main()