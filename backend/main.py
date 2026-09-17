"""FastAPI application: API layer + static frontend serving + live SSE stream.

Safe by default: responses are simulated, auto-response is disabled unless
explicitly configured. Uploaded data is validated, size-limited, never executed,
and kept strictly separate from demo data via the ``dataset`` parameter.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles

from . import analytics, audit
from . import database as db
from . import demo as demo_mod
from . import evaluation, ingestion, reports, security_assessment
from .agents import memory_agent, orchestrator, threat_intel_agent
from .config import DATA_DIR, FRONTEND_DIR, config

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    threat_intel_agent.seed_from_file()
    audit.log("system.startup", detail=f"{config.APP_NAME} started "
              f"(APP_ENV={config.APP_ENV})")
    yield


app = FastAPI(title=config.APP_NAME, version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS,
                   allow_methods=["*"], allow_headers=["*"])


def _dataset(value: str) -> str:
    return "demo" if (value or "").lower() == "demo" else "real"


# --------------------------------------------------------------------------- #
# System / config
# --------------------------------------------------------------------------- #
@app.get("/api/config")
def get_config():
    return {
        "app_name": config.APP_NAME, "app_short": config.APP_SHORT,
        "app_env": config.APP_ENV,
        "auto_response_enabled": config.AUTO_RESPONSE_ENABLED,
        "response_simulation": config.RESPONSE_SIMULATION,
        "risk_threshold": config.RISK_THRESHOLD,
        "autonomy_level": config.AUTONOMY_LEVEL,
        "max_events": config.MAX_EVENTS,
        "external_ti_configured": threat_intel_agent.EXTERNAL_CONFIGURED,
    }


# --------------------------------------------------------------------------- #
# Dashboard / analytics
# --------------------------------------------------------------------------- #
@app.get("/api/dashboard")
def dashboard(dataset: str = "real"):
    return analytics.dashboard(_dataset(dataset))


@app.get("/api/analytics")
def get_analytics(dataset: str = "real"):
    ds = _dataset(dataset)
    return {"summary": analytics.dashboard(ds), "charts": analytics.charts(ds)}


# --------------------------------------------------------------------------- #
# Events / ingestion
# --------------------------------------------------------------------------- #
@app.get("/api/events")
def list_events(dataset: str = "real", limit: int = 100, offset: int = 0):
    ds = _dataset(dataset)
    limit = max(1, min(limit, 1000))
    rows = db.query(
        "SELECT * FROM events WHERE dataset=? ORDER BY id DESC LIMIT ? OFFSET ?",
        (ds, limit, offset))
    total = db.scalar("SELECT COUNT(*) FROM events WHERE dataset=?", (ds,)) or 0
    return {"total": total, "events": rows}


@app.post("/api/events/upload")
async def upload_events(file: UploadFile = File(...),
                        dataset: str = Form("real"),
                        fmt: str | None = Form(None)):
    ds = _dataset(dataset)
    raw = await file.read()
    if len(raw) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit "
                            f"{config.MAX_UPLOAD_BYTES} bytes).")
    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover
        raise HTTPException(400, f"Could not decode file: {exc}")
    try:
        summary = ingestion.ingest(content, file.filename or "upload", ds, fmt)
    except ingestion.IngestionError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(400, f"Ingestion failed: {exc}")
    audit.log("events.uploaded", actor="analyst",
              detail=f"{summary['stored']} events from {summary['filename']}",
              dataset=ds)
    return summary


@app.get("/api/samples")
def list_samples():
    files = sorted(p.name for p in DATA_DIR.glob("sample_*")
                   if p.suffix in (".csv", ".json"))
    return {"samples": files}


@app.post("/api/samples/load")
def load_sample(payload: dict = Body(default={})):
    from .security import safe_filename
    name = safe_filename(payload.get("name", "sample_events.csv"))
    path = DATA_DIR / name
    if not path.exists() or path.suffix not in (".csv", ".json"):
        raise HTTPException(404, "Sample not found.")
    content = path.read_text(encoding="utf-8", errors="replace")
    try:
        summary = ingestion.ingest(content, name, "real")
    except ingestion.IngestionError as exc:
        raise HTTPException(400, str(exc))
    audit.log("events.uploaded", actor="analyst",
              detail=f"Bundled sample '{name}' -> {summary['stored']} events",
              dataset="real")
    return summary


@app.post("/api/detection/run")
def run_detection(payload: dict = Body(default={})):
    ds = _dataset(payload.get("dataset", "real"))
    batch = payload.get("batch_id")
    result = orchestrator.run_detection(ds, batch)
    result["dataset"] = ds
    return result


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #
@app.get("/api/incidents")
def list_incidents(dataset: str = "real", severity: str | None = None,
                   status: str | None = None, attack_type: str | None = None,
                   host: str | None = None, user: str | None = None,
                   min_risk: float = 0.0, limit: int = 200):
    ds = _dataset(dataset)
    sql = "SELECT * FROM incidents WHERE dataset=?"
    params: list = [ds]
    if severity:
        sql += " AND severity=?"; params.append(severity)
    if status:
        sql += " AND status=?"; params.append(status)
    if attack_type:
        sql += " AND attack_type=?"; params.append(attack_type)
    if min_risk:
        sql += " AND risk_score>=?"; params.append(min_risk)
    if host:
        sql += " AND affected_hosts LIKE ?"; params.append(f"%{host}%")
    if user:
        sql += " AND affected_users LIKE ?"; params.append(f"%{user}%")
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(max(1, min(limit, 500)))
    rows = db.query(sql, params)
    for r in rows:
        for f in ("affected_hosts", "affected_users", "source_ips",
                  "destination_ips", "mitre"):
            r[f] = db.jload(r[f], [])
    return {"count": len(rows), "incidents": rows}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = db.query_one("SELECT * FROM incidents WHERE incident_id=?", (incident_id,))
    if not inc:
        raise HTTPException(404, "Incident not found")
    for f in ("affected_hosts", "affected_users", "source_ips",
              "destination_ips", "mitre"):
        inc[f] = db.jload(inc[f], [])
    return inc


@app.get("/api/incidents/{incident_id}/evidence")
def get_evidence(incident_id: str):
    rows = db.query(
        "SELECT * FROM evidence WHERE incident_id=? AND kind!='analysis' "
        "ORDER BY id", (incident_id,))
    return {"count": len(rows), "evidence": rows}


@app.get("/api/incidents/{incident_id}/timeline")
def get_timeline(incident_id: str):
    ctx = orchestrator.build_context(incident_id)
    if not ctx:
        raise HTTPException(404, "Incident not found")
    from .agents.investigation_agent import build_timeline
    return {"timeline": build_timeline(ctx.events)}


@app.get("/api/incidents/{incident_id}/analysis")
def get_incident_analysis(incident_id: str):
    a = orchestrator.get_analysis(incident_id)
    if a is None:
        raise HTTPException(404, "No analysis yet — run investigation first.")
    return a


@app.get("/api/incidents/{incident_id}/graph")
def get_graph(incident_id: str):
    ctx = orchestrator.build_context(incident_id)
    if not ctx:
        raise HTTPException(404, "Incident not found")
    from .agents.correlation_agent import build_graph
    return build_graph(ctx)


@app.get("/api/incidents/{incident_id}/chain")
def get_attack_chain(incident_id: str):
    ctx = orchestrator.build_context(incident_id)
    if not ctx:
        raise HTTPException(404, "Incident not found")
    return {"attack_chain": orchestrator.build_attack_chain(ctx)}


@app.get("/api/incidents/{incident_id}/effects")
def get_response_effects(incident_id: str):
    """Simulated response effects (kept separate from immutable events)."""
    return {"effects": db.query(
        "SELECT * FROM response_effects WHERE incident_id=? ORDER BY id",
        (incident_id,))}


@app.get("/api/incidents/{incident_id}/responses")
def get_incident_responses(incident_id: str):
    rows = db.query(
        "SELECT * FROM responses WHERE incident_id=? ORDER BY created_at",
        (incident_id,))
    return {"responses": rows}


@app.get("/api/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: str):
    return {"audit": audit.for_incident(incident_id)}


@app.post("/api/incidents/{incident_id}/investigate")
def investigate(incident_id: str):
    result = orchestrator.investigate(incident_id)
    if result is None:
        raise HTTPException(404, "Incident not found")
    return result


@app.post("/api/incidents/{incident_id}/response/plan")
def plan_response(incident_id: str):
    # planning is produced as part of investigation; (re)run it.
    result = orchestrator.investigate(incident_id)
    if result is None:
        raise HTTPException(404, "Incident not found")
    return {"plans": result["plans"],
            "recommended_response_id": result["recommended_response_id"]}


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #
@app.get("/api/responses")
def list_responses(dataset: str = "real"):
    ds = _dataset(dataset)
    rows = db.query(
        "SELECT r.*, i.attack_type, i.severity FROM responses r "
        "JOIN incidents i ON r.incident_id=i.incident_id WHERE i.dataset=? "
        "ORDER BY r.updated_at DESC", (ds,))
    buckets: dict = {"pending": [], "awaiting_approval": [], "approved": [],
                     "executed": [], "failed": [], "rejected": []}
    for r in rows:
        st = r["status"]
        key = ("pending" if st in ("planned", "validated") else st)
        buckets.setdefault(key, []).append(r)
    return {"responses": rows, "buckets": buckets}


@app.post("/api/responses/{response_id}/validate")
def validate_response(response_id: str):
    v = orchestrator.revalidate_response(response_id)
    if v is None:
        raise HTTPException(404, "Response not found")
    return v


@app.post("/api/responses/{response_id}/approve")
def approve_response(response_id: str, payload: dict = Body(default={})):
    analyst = payload.get("analyst", "analyst")
    r = orchestrator.approve_response(response_id, analyst)
    if r is None:
        raise HTTPException(404, "Response not found")
    if isinstance(r, dict) and r.get("error"):
        raise HTTPException(400, r["error"])
    return r


@app.post("/api/responses/{response_id}/simulate")
def simulate_response(response_id: str, payload: dict = Body(default={})):
    analyst = payload.get("analyst", "analyst")
    r = orchestrator.simulate_response(response_id, analyst)
    if r is None:
        raise HTTPException(404, "Response not found")
    if r.get("error"):
        raise HTTPException(400, r["error"] if not r.get("requires_approval")
                            else "Human approval required before simulation.")
    return r


# --------------------------------------------------------------------------- #
# Demo mode
# --------------------------------------------------------------------------- #
@app.get("/api/demo/state")
def demo_state():
    return demo_mod.get_state()


@app.post("/api/demo/start")
async def demo_start():
    demo_mod.engine.start()   # async so create_task has a running loop
    return demo_mod.get_state()


@app.post("/api/demo/stop")
async def demo_stop():
    demo_mod.engine.stop()
    return demo_mod.get_state()


@app.post("/api/demo/pause")
async def demo_pause():
    demo_mod.engine.pause()
    return demo_mod.get_state()


@app.post("/api/demo/resume")
async def demo_resume():
    demo_mod.engine.resume()
    return demo_mod.get_state()


@app.post("/api/demo/reset")
async def demo_reset():
    demo_mod.engine.reset()
    return demo_mod.get_state()


@app.post("/api/demo/step")
def demo_step(payload: dict = Body(default={})):
    """Generate a single demo scenario immediately (useful for tests / manual)."""
    scenario = payload.get("scenario") or "brute_force"
    if scenario not in demo_mod.SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Choose from {demo_mod.SCENARIOS}")
    return demo_mod.load_scenario(scenario)


# --------------------------------------------------------------------------- #
# Audit / memory / threat intel / search
# --------------------------------------------------------------------------- #
@app.get("/api/audit")
def get_audit(dataset: str | None = None, limit: int = 200):
    ds = _dataset(dataset) if dataset else None
    return {"audit": audit.recent(limit, ds)}


@app.get("/api/security-assessment")
def get_security_assessment(dataset: str = "real"):
    """Latest posture assessment for the dataset (real by default)."""
    ds = _dataset(dataset)
    bundle = security_assessment.latest(ds)
    if bundle is None:
        return {"assessment": None, "dataset": ds,
                "message": "No assessment yet. Run one to analyse the "
                           f"{ds} dataset."}
    bundle["diff"] = security_assessment.diff(ds)
    return bundle


@app.post("/api/security-assessment/run")
def run_security_assessment(payload: dict = Body(default={})):
    ds = _dataset(payload.get("dataset", "real"))
    data_source = payload.get("data_source")
    events = db.scalar("SELECT COUNT(*) FROM events WHERE dataset=?", (ds,)) or 0
    if events == 0:
        raise HTTPException(400, f"No {ds} data to assess. Ingest data first.")
    bundle = security_assessment.run_assessment(ds, data_source)
    bundle["diff"] = security_assessment.diff(ds)
    return bundle


@app.get("/api/security-assessment/history")
def security_assessment_history(dataset: str = "real"):
    return {"history": security_assessment.history(_dataset(dataset))}


@app.get("/api/security-assessment/{assessment_id}")
def security_assessment_by_id(assessment_id: str):
    bundle = security_assessment.get_assessment(assessment_id)
    if bundle is None:
        raise HTTPException(404, "Assessment not found")
    return bundle


@app.get("/api/evaluation")
def get_evaluation(dataset: str = "real"):
    """Detection quality metrics vs labelled ground truth (real by default)."""
    return evaluation.evaluate(_dataset(dataset))


@app.get("/api/memory")
def get_memory():
    return {"experiences": memory_agent.all_experiences()}


@app.get("/api/memory/strategies")
def get_strategy_stats(attack_type: str | None = None):
    """Measured per-strategy success rates that drive adaptive learning."""
    return {"strategies": memory_agent.strategy_stats(attack_type)}


@app.post("/api/memory/{experience_id}/trust")
def set_memory_trust(experience_id: str, payload: dict = Body(...)):
    status = payload.get("status")
    ok = memory_agent.set_trust(experience_id, status)
    if not ok:
        raise HTTPException(400, "Invalid experience_id or status.")
    return {"experience_id": experience_id, "status": status}


@app.get("/api/threat-intel/lookup")
def ti_lookup(indicator: str, type: str = "ip"):
    if not threat_intel_agent.EXTERNAL_CONFIGURED:
        res = threat_intel_agent.lookup(indicator, type)
        res["external_note"] = "External threat intelligence not configured."
        return res
    return threat_intel_agent.lookup(indicator, type)


@app.get("/api/search")
def search(q: str, dataset: str = "real"):
    ds = _dataset(dataset)
    q = q.strip()
    if not q:
        return {"results": []}
    results = []
    like = f"%{q}%"
    # incidents
    incs = db.query(
        "SELECT incident_id, attack_type, severity, status FROM incidents "
        "WHERE dataset=? AND (incident_id LIKE ? OR attack_type LIKE ? "
        "OR source_ips LIKE ? OR affected_users LIKE ? OR affected_hosts LIKE ? "
        "OR mitre LIKE ?)", (ds, like, like, like, like, like, like))
    for i in incs:
        results.append({"type": "incident", "incident_id": i["incident_id"],
                        "label": f"{i['incident_id']} — {i['attack_type']} "
                                 f"({i['severity']}, {i['status']})"})
    # events -> map to incident if possible
    evs = db.query(
        "SELECT id, event_type, source_ip, user, host FROM events WHERE dataset=? "
        "AND (source_ip LIKE ? OR user LIKE ? OR host LIKE ? OR event_id LIKE ?) "
        "LIMIT 25", (ds, like, like, like, like))
    for e in evs:
        inc = db.query_one(
            "SELECT incident_id FROM evidence WHERE event_ref=? LIMIT 1", (e["id"],))
        results.append({"type": "event", "event_id": e["id"],
                        "incident_id": inc["incident_id"] if inc else None,
                        "label": f"event #{e['id']} {e['event_type']} "
                                 f"{e.get('source_ip') or ''} {e.get('user') or ''}"})
    return {"results": results[:50]}


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
@app.get("/api/export/incident/{incident_id}.md")
def export_md(incident_id: str):
    md = reports.markdown_report(incident_id)
    if md is None:
        raise HTTPException(404, "Incident not found")
    return PlainTextResponse(md, headers={
        "Content-Disposition": f"attachment; filename={incident_id}.md"})


@app.get("/api/export/incident/{incident_id}.json")
def export_json(incident_id: str):
    b = reports.incident_bundle(incident_id)
    if b is None:
        raise HTTPException(404, "Incident not found")
    return JSONResponse(b, headers={
        "Content-Disposition": f"attachment; filename={incident_id}.json"})


@app.get("/api/export/incidents.csv")
def export_incidents_csv(dataset: str = "real"):
    ds = _dataset(dataset)
    return PlainTextResponse(reports.incidents_csv(ds), media_type="text/csv",
                             headers={"Content-Disposition":
                                      f"attachment; filename=incidents_{ds}.csv"})


@app.get("/api/export/audit.csv")
def export_audit_csv(dataset: str | None = None):
    import csv
    import io
    rows = audit.recent(5000, _dataset(dataset) if dataset else None)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "incident_id", "actor", "action", "detail", "dataset"])
    for r in rows:
        w.writerow([r["ts"], r["incident_id"], r["actor"], r["action"],
                    r["detail"], r["dataset"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition":
                                      "attachment; filename=audit_log.csv"})


# --------------------------------------------------------------------------- #
# Live updates (SSE)
# --------------------------------------------------------------------------- #
@app.get("/api/stream")
async def stream(dataset: str = "real"):
    ds = _dataset(dataset)

    async def event_gen():
        while True:
            payload = {
                "dashboard": analytics.dashboard(ds),
                "demo": demo_mod.get_state(),
            }
            yield f"data: {json.dumps(payload, default=str)}\n\n"
            await asyncio.sleep(2.5)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# --------------------------------------------------------------------------- #
# Frontend (build-free SPA)
# --------------------------------------------------------------------------- #
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def index():
    idx = FRONTEND_DIR / "index.html"
    if idx.exists():
        return FileResponse(str(idx))
    return JSONResponse({"message": f"{config.APP_NAME} API is running.",
                         "docs": "/docs"})


@app.get("/health")
def health():
    return {"status": "ok", "app": config.APP_NAME}
