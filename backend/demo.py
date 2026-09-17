"""Demo Mode — synthetic, clearly-labelled scenario generator.

All events produced here are stored with ``dataset='demo'`` and are NEVER mixed
with real uploaded data. This is synthetic DEMO DATA for demonstration only; it
is never presented as real company security data.

The engine runs as a background asyncio task. Each tick it emits one attack
scenario, stores the events, runs detection over the demo dataset, and
auto-investigates any newly created incidents so every page populates live.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import random

from . import audit
from . import database as db
from .agents import orchestrator
from .config import config
from .ingestion import store_events
from .models import new_batch_id, now_iso

SCENARIOS = [
    "brute_force", "credential_compromise", "port_scan",
    "malware_execution", "data_exfiltration", "lateral_movement",
]
SCENARIO_LABELS = {
    "brute_force": "Brute Force",
    "credential_compromise": "Credential Compromise",
    "port_scan": "Port Scan",
    "malware_execution": "Malware Execution",
    "data_exfiltration": "Data Exfiltration",
    "lateral_movement": "Lateral Movement",
}

_ATTACKER_IPS = ["203.0.113.66", "203.0.113.77", "45.155.205.233",
                 "198.51.100.23", "198.51.100.199", "192.0.2.44"]
_USERS = ["jdoe", "asmith", "admin", "svc_backup", "mkhan", "rlee"]
_HOSTS = ["WKS-201", "WKS-330", "DC-01", "DB-PROD-1", "FIN-APP-2", "WKS-118"]


def _ev(ts, **kw) -> dict:
    base = {
        "timestamp": ts.isoformat(),
        "event_id": None, "source": "demo-sensor", "host": None, "user": None,
        "source_ip": None, "destination_ip": None, "port": None,
        "protocol": None, "event_type": None, "action": None, "status": None,
        "severity": None, "process": None, "command": None, "bytes": None,
        "authentication_result": None, "raw_event": None,
    }
    base.update(kw)
    if not base["raw_event"]:
        base["raw_event"] = "DEMO " + " ".join(
            f"{k}={v}" for k, v in kw.items() if v is not None)
    return base


def generate(scenario: str, base: _dt.datetime | None = None) -> list[dict]:
    base = base or _dt.datetime.now()
    ip = random.choice(_ATTACKER_IPS)
    user = random.choice(_USERS)
    host = random.choice(_HOSTS)
    evs: list[dict] = []

    if scenario == "brute_force":
        n = random.randint(8, 20)
        for i in range(n):
            evs.append(_ev(base + _dt.timedelta(seconds=i * 6), host=host,
                           user=user, source_ip=ip, event_type="login",
                           action="logon", status="failure", severity="medium",
                           protocol="ssh", authentication_result="failure"))
    elif scenario == "credential_compromise":
        n = random.randint(10, 16)
        for i in range(n):
            evs.append(_ev(base + _dt.timedelta(seconds=i * 5), host=host,
                           user=user, source_ip=ip, event_type="login",
                           status="failure", severity="high",
                           authentication_result="failure"))
        evs.append(_ev(base + _dt.timedelta(seconds=n * 5 + 4), host=host,
                       user=user, source_ip=ip, event_type="login",
                       status="success", severity="high",
                       authentication_result="success"))
        evs.append(_ev(base + _dt.timedelta(seconds=n * 5 + 20), host=host,
                       user=user, source_ip=ip, event_type="process",
                       process="cmd.exe", command="whoami /priv",
                       severity="high"))
    elif scenario == "port_scan":
        ports = random.sample(range(20, 9000), random.randint(14, 30))
        for i, p in enumerate(ports):
            evs.append(_ev(base + _dt.timedelta(seconds=i * 2), host=host,
                           source_ip=ip, destination_ip="10.0.0.15", port=p,
                           protocol="tcp", event_type="connection",
                           action="syn", status="blocked", severity="low"))
    elif scenario == "malware_execution":
        evs.append(_ev(base, host=host, user=user, source_ip=ip,
                       event_type="malware", process="mimikatz.exe",
                       command="mimikatz.exe sekurlsa::logonpasswords",
                       severity="critical"))
        evs.append(_ev(base + _dt.timedelta(seconds=8), host=host, user=user,
                       event_type="process", process="powershell.exe",
                       command="powershell -nop -w hidden -enc SQBFAFgA",
                       severity="high"))
    elif scenario == "data_exfiltration":
        dst = "198.51.100.199"
        for i in range(random.randint(3, 6)):
            evs.append(_ev(base + _dt.timedelta(seconds=i * 15), host=host,
                           user=user, source_ip="10.0.0.15",
                           destination_ip=dst, port=443, protocol="https",
                           event_type="exfiltration", action="upload",
                           bytes=random.randint(6_000_000, 40_000_000),
                           severity="high"))
    elif scenario == "lateral_movement":
        for i in range(random.randint(3, 6)):
            h = random.choice(_HOSTS)
            evs.append(_ev(base + _dt.timedelta(seconds=i * 30), host=h,
                           user=user, source_ip="10.0.0.15",
                           event_type="remote_logon", action="rdp",
                           status="success", severity="high",
                           authentication_result="success"))
    return evs


def load_scenario(scenario: str) -> dict:
    """Generate a single scenario, store it, detect & investigate. Returns summary."""
    events = generate(scenario)
    batch = new_batch_id()
    store_events(events, "demo", batch)
    result = orchestrator.run_detection("demo", batch)
    for inc_id in result["incidents_created"]:
        orchestrator.investigate(inc_id)
    _bump_state(len(events), len(result["incidents_created"]))
    return {"scenario": scenario, "events": len(events),
            "incidents": result["incidents_created"]}


def _bump_state(events: int, incidents: int) -> None:
    db.execute(
        "UPDATE demo_state SET events_generated=events_generated+?, "
        "incidents_generated=incidents_generated+?, updated_at=? WHERE id=1",
        (events, incidents, now_iso()))


def get_state() -> dict:
    row = db.query_one("SELECT * FROM demo_state WHERE id=1")
    return dict(row) if row else {"status": "stopped"}


class DemoEngine:
    """Background asyncio-driven demo generator."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = asyncio.Event()
        self._stop = False

    async def _loop(self):
        while not self._stop:
            await self._running.wait()
            if self._stop:
                break
            state = get_state()
            if (state.get("incidents_generated") or 0) >= config.DEMO_MAX_INCIDENTS:
                self.pause()
                audit.log("demo.autopaused", actor="Demo Engine",
                          detail="Reached DEMO_MAX_INCIDENTS.", dataset="demo")
                continue
            scenario = random.choice(SCENARIOS)
            try:
                await asyncio.to_thread(load_scenario, scenario)
            except Exception as exc:  # never let the demo crash the app
                audit.log("demo.error", actor="Demo Engine",
                          detail=str(exc)[:300], dataset="demo")
            await asyncio.sleep(config.DEMO_TICK_SECONDS)

    def ensure_task(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    def start(self):
        self.ensure_task()
        self._stop = False
        self._running.set()
        db.execute("UPDATE demo_state SET status='running', started_at=?, "
                   "updated_at=? WHERE id=1", (now_iso(), now_iso()))
        audit.log("demo.started", actor="Demo Engine", dataset="demo")

    def pause(self):
        self._running.clear()
        db.execute("UPDATE demo_state SET status='paused', updated_at=? WHERE id=1",
                   (now_iso(),))
        audit.log("demo.paused", actor="Demo Engine", dataset="demo")

    def resume(self):
        self.ensure_task()
        self._running.set()
        db.execute("UPDATE demo_state SET status='running', updated_at=? WHERE id=1",
                   (now_iso(),))
        audit.log("demo.resumed", actor="Demo Engine", dataset="demo")

    def stop(self):
        self._running.clear()
        db.execute("UPDATE demo_state SET status='stopped', updated_at=? WHERE id=1",
                   (now_iso(),))
        audit.log("demo.stopped", actor="Demo Engine", dataset="demo")

    def reset(self):
        self.stop()
        db.reset_dataset("demo")
        db.execute("UPDATE demo_state SET status='stopped', events_generated=0, "
                   "incidents_generated=0, updated_at=? WHERE id=1", (now_iso(),))
        audit.log("demo.reset", actor="Demo Engine",
                  detail="All demo data cleared.", dataset="demo")


engine = DemoEngine()
