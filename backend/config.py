"""Central configuration for the Adaptive AI Cyber Defense System.

All values can be overridden by environment variables. Defaults are chosen so
the system is SAFE by default: real destructive actions are never executed and
responses are always simulated.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR.mkdir(exist_ok=True)


def _get_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _get_bool_any(names: list[str], default: bool) -> bool:
    """Read the first environment variable that is set among ``names``.

    Lets us introduce new canonical names (e.g. AUTO_RESPONSE) while remaining
    backward-compatible with the older names (AUTO_RESPONSE_ENABLED).
    """
    for n in names:
        if os.environ.get(n) is not None:
            return _get_bool(n, default)
    return default


def _get_int_any(names: list[str], default: int) -> int:
    for n in names:
        if os.environ.get(n) is not None:
            return _get_int(n, default)
    return default


class Config:
    # --- Application ---
    APP_ENV = os.environ.get("APP_ENV", "development")
    APP_NAME = "Adaptive AI Cyber Defense System"
    APP_SHORT = "AI-SOC"
    IS_PRODUCTION = APP_ENV.lower() in {"production", "prod"}

    # --- Database ---
    # DATABASE_URL takes precedence when set (e.g. sqlite:////data/soc.db). Only
    # sqlite URLs are honoured today; the value documents future PG migration.
    DATABASE_URL = os.environ.get("DATABASE_URL", "")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "soc.db"))
    if DATABASE_URL.startswith("sqlite:///"):
        DATABASE_PATH = DATABASE_URL.replace("sqlite:///", "", 1)

    # --- Ingestion limits ---
    MAX_EVENTS = _get_int("MAX_EVENTS", 50000)
    MAX_UPLOAD_BYTES = _get_int("MAX_UPLOAD_BYTES", 500 * 1024 * 1024)  # 500 MB

    # --- Demo mode ---
    DEMO_MODE = _get_bool("DEMO_MODE", True)
    DEMO_TICK_SECONDS = _get_float("DEMO_TICK_SECONDS", 3.0)
    DEMO_MAX_INCIDENTS = _get_int("DEMO_MAX_INCIDENTS", 200)

    # --- Response / autonomy (SAFE DEFAULTS) ---
    # New canonical name AUTO_RESPONSE; legacy AUTO_RESPONSE_ENABLED still works.
    AUTO_RESPONSE_ENABLED = _get_bool_any(
        ["AUTO_RESPONSE", "AUTO_RESPONSE_ENABLED"], False)
    RESPONSE_SIMULATION = _get_bool("RESPONSE_SIMULATION", True)

    # Risk threshold (0..1) above which an incident is considered high risk.
    RISK_THRESHOLD = _get_float("RISK_THRESHOLD", 0.70)

    # Maximum autonomy level the system is *allowed* to use.
    #   0 Observe, 1 Recommend, 2 Human approval, 3 Auto low-risk, 4 Controlled autonomous
    AUTONOMY_LEVEL = _get_int_any(["AUTONOMY_LEVEL_CAP", "AUTONOMY_LEVEL"], 3)

    # --- Threat intelligence ---
    EXTERNAL_TI_ENABLED = _get_bool("EXTERNAL_TI_ENABLED", False)

    # --- Anomaly detection ---
    ANOMALY_CONTAMINATION = _get_float("ANOMALY_CONTAMINATION", 0.08)

    # --- Real datasets (configurable; no hard-coded local file path) ---
    # Directory where the user drops real CIC-IDS / CSE-CIC-IDS CSV files.
    DATASET_DIR = os.environ.get("DATASET_DIR", str(DATA_DIR / "datasets"))

    # --- Server / deployment ---
    # Bind 0.0.0.0 in production (containers/Render); localhost for local dev.
    HOST = os.environ.get("HOST", "0.0.0.0" if IS_PRODUCTION else "127.0.0.1")
    PORT = _get_int("PORT", 8000)
    # Comma-separated CORS origins; "*" by default for the local demo.
    CORS_ORIGINS = [o.strip() for o in
                    os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]


config = Config()

