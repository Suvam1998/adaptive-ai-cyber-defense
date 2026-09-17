"""API-level tests using FastAPI TestClient."""
import datetime as dt
import io

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def _csv_bytes():
    base = dt.datetime(2026, 9, 15, 10, 31, 0)
    lines = ["timestamp,event_type,user,source_ip,status,authentication_result"]
    for i in range(14):
        t = (base + dt.timedelta(seconds=i * 6)).isoformat()
        lines.append(f"{t},login,jdoe,203.0.113.66,failure,failure")
    lines.append(f"{(base + dt.timedelta(seconds=90)).isoformat()},login,jdoe,"
                 f"203.0.113.66,success,success")
    return "\n".join(lines).encode()


def test_config_endpoint_safe_defaults():
    r = client.get("/api/config")
    assert r.status_code == 200
    body = r.json()
    assert body["response_simulation"] is True
    assert body["auto_response_enabled"] is False


def test_upload_detect_investigate_flow():
    files = {"file": ("bf.csv", io.BytesIO(_csv_bytes()), "text/csv")}
    r = client.post("/api/events/upload", files=files, data={"dataset": "real"})
    assert r.status_code == 200, r.text
    assert r.json()["stored"] == 15

    r = client.post("/api/detection/run", json={"dataset": "real"})
    assert r.status_code == 200
    incs = r.json()["incidents_created"]
    assert incs
    inc = incs[0]

    r = client.post(f"/api/incidents/{inc}/investigate")
    assert r.status_code == 200
    a = r.json()
    assert a["risk"]["total"] > 0

    # evidence / timeline / graph / analysis endpoints
    assert client.get(f"/api/incidents/{inc}/evidence").status_code == 200
    assert client.get(f"/api/incidents/{inc}/timeline").status_code == 200
    assert client.get(f"/api/incidents/{inc}/graph").status_code == 200
    assert client.get(f"/api/incidents/{inc}/analysis").status_code == 200

    # response lifecycle
    rid = a["recommended_response_id"]
    if a["autonomy"]["requires_approval"]:
        client.post(f"/api/responses/{rid}/approve", json={})
    r = client.post(f"/api/responses/{rid}/simulate", json={})
    assert r.status_code == 200
    assert r.json()["outcome"] in ("SUCCESS", "PARTIAL")

    # analytics + audit reflect the incident
    assert client.get("/api/dashboard?dataset=real").json()["threats_detected"] >= 1
    assert client.get(f"/api/incidents/{inc}/audit").json()["audit"]


def test_upload_too_large_rejected(monkeypatch):
    from backend.config import config
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 10)
    files = {"file": ("big.csv", io.BytesIO(b"x" * 100), "text/csv")}
    r = client.post("/api/events/upload", files=files, data={"dataset": "real"})
    assert r.status_code == 413


def test_bad_upload_returns_400():
    files = {"file": ("bad.json", io.BytesIO(b"{not json"), "text/csv")}
    r = client.post("/api/events/upload", files=files,
                    data={"dataset": "real", "fmt": "json"})
    assert r.status_code == 400


def test_demo_step_and_state():
    r = client.post("/api/demo/step", json={"scenario": "port_scan"})
    assert r.status_code == 200
    assert r.json()["events"] > 0
    assert client.get("/api/demo/state").status_code == 200
    # demo incidents are in demo dataset only
    assert client.get("/api/incidents?dataset=demo").json()["count"] >= 1


def test_threat_intel_lookup():
    r = client.get("/api/threat-intel/lookup?indicator=203.0.113.66&type=ip")
    assert r.status_code == 200
    assert r.json()["reputation"] == "malicious"
    r2 = client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip")
    assert r2.json()["reputation"] == "unknown"


def test_search_and_export():
    files = {"file": ("bf.csv", io.BytesIO(_csv_bytes()), "text/csv")}
    client.post("/api/events/upload", files=files, data={"dataset": "real"})
    client.post("/api/detection/run", json={"dataset": "real"})
    r = client.get("/api/search?q=203.0.113.66&dataset=real")
    assert r.status_code == 200
    r = client.get("/api/export/incidents.csv?dataset=real")
    assert r.status_code == 200 and "incident_id" in r.text
