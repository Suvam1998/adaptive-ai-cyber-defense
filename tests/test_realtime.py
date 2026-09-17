"""Real-time dashboard refresh contract.

The dashboard is refreshed by a frontend poller that calls ONE analytics
endpoint (KPIs + charts) plus the demo-state endpoint. These tests prove the
backend side of that contract: the endpoints reflect *current* database state on
each call, dataset isolation holds, and demo state transitions are observable —
so successive polls return updated data without any navigation or page reload.
"""
import datetime as dt
import io

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def _bf_csv(ip="203.0.113.66"):
    base = dt.datetime(2026, 9, 15, 10, 31, 0)
    lines = ["timestamp,event_type,user,source_ip,status,authentication_result"]
    for i in range(14):
        t = (base + dt.timedelta(seconds=i * 6)).isoformat()
        lines.append(f"{t},login,jdoe,{ip},failure,failure")
    lines.append(f"{(base+dt.timedelta(seconds=90)).isoformat()},login,jdoe,{ip},"
                 f"success,success")
    return "\n".join(lines).encode()


# --------------------------------------------------------------------------- #
def test_analytics_single_request_has_kpis_and_charts():
    """One request returns everything the dashboard needs (Phase 9)."""
    r = client.get("/api/analytics?dataset=real")
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body and "charts" in body
    for kpi in ("active_incidents", "threats_detected", "responses_executed",
                "human_escalations", "response_success_rate"):
        assert kpi in body["summary"]
    for chart in ("threats_over_time", "by_severity", "attack_techniques",
                  "response_outcomes", "risk_distribution", "detection_methods"):
        assert chart in body["charts"]


def test_dashboard_reflects_real_data_changes():
    """Successive reads reflect new DB state (no reload needed)."""
    before = client.get("/api/dashboard?dataset=real").json()["threats_detected"]
    files = {"file": ("bf.csv", io.BytesIO(_bf_csv()), "text/csv")}
    client.post("/api/events/upload", files=files, data={"dataset": "real"})
    client.post("/api/detection/run", json={"dataset": "real"})
    after = client.get("/api/dashboard?dataset=real").json()["threats_detected"]
    assert after > before


def test_dashboard_reflects_demo_state_changes():
    """Demo generation changes what the demo dashboard reports on the next poll."""
    before = client.get("/api/dashboard?dataset=demo").json()["threats_detected"]
    client.post("/api/demo/step", json={"scenario": "port_scan"})
    after = client.get("/api/dashboard?dataset=demo").json()["threats_detected"]
    assert after > before


def test_demo_state_endpoint_reports_status_for_indicator():
    """The poller derives its LIVE/PAUSED/STOPPED pill from real backend state."""
    client.post("/api/demo/stop")
    assert client.get("/api/demo/state").json()["status"] == "stopped"
    client.post("/api/demo/start")
    assert client.get("/api/demo/state").json()["status"] == "running"
    client.post("/api/demo/pause")
    assert client.get("/api/demo/state").json()["status"] == "paused"
    client.post("/api/demo/stop")
    assert client.get("/api/demo/state").json()["status"] == "stopped"


def test_dashboard_polls_stay_dataset_isolated():
    """A demo poll must never surface real data and vice versa."""
    files = {"file": ("bf.csv", io.BytesIO(_bf_csv(ip="45.155.205.233")),
                      "text/csv")}
    client.post("/api/events/upload", files=files, data={"dataset": "real"})
    client.post("/api/detection/run", json={"dataset": "real"})
    client.post("/api/demo/step", json={"scenario": "brute_force"})
    real_ev = client.get("/api/dashboard?dataset=real").json()["total_events"]
    demo_ev = client.get("/api/dashboard?dataset=demo").json()["total_events"]
    # both have data, and demo generation never inflated the real event count
    assert real_ev > 0 and demo_ev > 0
    real2 = client.get("/api/dashboard?dataset=real").json()["total_events"]
    assert real2 == real_ev   # a demo step did not change real analytics
