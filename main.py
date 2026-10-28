"""
UBA :: entry point
-------------------------
API + dashboard `config.yaml` / runs in environment files `api.host` and `api.port`.

    python main.py                      # http://127.0.0.1:8088
    UBA_API__PORT=9000 python main.py # different port

In the production environment this file is used to deploy the service of systemd 
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

import uvicorn

from src.config.config import get_settings


def setup_logging(settings) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(
            RotatingFileHandler(
                settings.logging.log_file,
                maxBytes=settings.logging.max_bytes,
                backupCount=settings.logging.backup_count,
                encoding="utf-8",
            )
        )
    except OSError as exc:  # e.g. file system is read-only - stdout/journald only can be used
        print(f"Warning: Could not open log file ({exc}); only stdout will be used.", file=sys.stderr)
    logging.basicConfig(
        level=getattr(logging, settings.logging.level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def main() -> None:
    settings = get_settings()
    setup_logging(settings)
    api = settings.api
    logging.getLogger("uba").info(
        "UBA starting: http://%s:%s (auth: %s)",
        api.host, api.port, "active" if api.basic_password else "disabled",
    )
    uvicorn.run(
        "src.api.app:create_app",
        factory=True,
        host=api.host,
        port=api.port,
        log_level=settings.logging.level.lower(),
    )


if __name__ == "__main__":
    main()
