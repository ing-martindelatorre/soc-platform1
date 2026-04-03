import logging
import sys


def setup_logging(level="INFO"):
    logger = logging.getLogger("soc-platform")

    if logger.handlers:
        return logger

    logger.setLevel(level.upper())

    handler = logging.StreamHandler(sys.stdout)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger