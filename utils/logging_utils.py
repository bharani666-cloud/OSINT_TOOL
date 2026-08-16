"""
Logging setup. Deliberately never logs request headers or credential
values -- only high-level "what happened" messages.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|bearer|secret|authorization)\s*[:=]\s*\S+"
)


class SecretRedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(record.msg))
        except Exception:
            pass
        return True


def setup_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("osint_tool")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = logging.FileHandler(log_dir / "collection.log", encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.addFilter(SecretRedactingFilter())
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.addFilter(SecretRedactingFilter())
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(console_handler)

    return logger
