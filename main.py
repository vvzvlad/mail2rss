"""Thin entry point (SPEC.md §10.1, §4.5).

If argv carries a known subcommand -> dispatch to the CLI (src/cli.py) and exit.
Otherwise start the FastAPI app (src/app.py) under uvicorn.

Kept deliberately thin: no application logic lives here. Settings are imported
lazily so that ``gen-secret`` — the command you run to CREATE the secret — works
before any environment is configured.
"""

from __future__ import annotations

import sys

# Subcommands handled by src/cli.py (SPEC.md §4.5).
KNOWN_COMMANDS = {"gen-secret", "folders", "url", "feeds", "opml", "check"}

# uvicorn bind address. BASE_URL (the public https URL) is a separate setting; the
# service itself always listens on all interfaces behind Traefik (SPEC.md §10.4).
HOST = "0.0.0.0"
PORT = 8000


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in KNOWN_COMMANDS:
        from src.cli import run_cli

        raise SystemExit(run_cli(argv))
    _run_server()


def _run_server() -> None:
    import uvicorn
    from loguru import logger

    from src.settings import settings

    logger.remove()
    logger.add(sys.stderr, level=settings.log_level)
    logger.info(f"mail2rss_starting: host {HOST}, port {PORT}")
    uvicorn.run("src.app:app", host=HOST, port=PORT, log_level=settings.log_level.lower())


if __name__ == "__main__":
    main()
