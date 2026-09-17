"""Launcher for the Adaptive AI Cyber Defense System.

Finds a free port (starting at PORT / 8000), prints the URL, and serves the
FastAPI app with uvicorn. Works on Windows without any virtual environment.

    python run.py
"""
from __future__ import annotations

import socket
import sys

from backend.config import config


def find_free_port(start: int, host: str = "127.0.0.1", tries: int = 50) -> int:
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port found in range {start}-{start + tries}.")


def main() -> None:
    import uvicorn

    host = config.HOST
    # In production (Render/containers) bind the platform-provided $PORT exactly
    # and do NOT scan for a free port. Locally, find a free port for convenience.
    if config.IS_PRODUCTION:
        port = config.PORT
    else:
        port = find_free_port(config.PORT, "127.0.0.1")
    print("=" * 60)
    print(f"  {config.APP_NAME}")
    print("  AI-assisted SOC — research/industry prototype")
    print("=" * 60)
    print(f"  Response simulation : {config.RESPONSE_SIMULATION}")
    print(f"  Auto-response       : {config.AUTO_RESPONSE_ENABLED}")
    print(f"  Autonomy level cap  : {config.AUTONOMY_LEVEL}")
    print("-" * 60)
    shown_host = "127.0.0.1" if host == "0.0.0.0" else host
    print(f"  Application running at:  http://{shown_host}:{port}")
    print(f"  API docs:                http://{shown_host}:{port}/docs")
    print("=" * 60)
    if port != config.PORT and not config.IS_PRODUCTION:
        print(f"  (Default port {config.PORT} was busy; using {port}.)")
    try:
        uvicorn.run("backend.main:app", host=host, port=port, log_level="info")
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
