"""Pytest fixtures. A throwaway SQLite DB is used so tests never touch soc.db."""
import os
import tempfile
import uuid

# Point the app at a temp DB BEFORE importing any backend module.
_TMP = os.path.join(tempfile.gettempdir(), f"soc_test_{uuid.uuid4().hex}.db")
os.environ["DATABASE_PATH"] = _TMP
os.environ["APP_ENV"] = "test"

import pytest  # noqa: E402

from backend import database as db  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    """Reset real+demo data before each test for isolation."""
    db.init_db()
    db.reset_dataset("real")
    db.reset_dataset("demo")
    db.execute("DELETE FROM memory")
    yield


def teardown_module():  # best-effort cleanup
    try:
        os.remove(_TMP)
    except OSError:
        pass
