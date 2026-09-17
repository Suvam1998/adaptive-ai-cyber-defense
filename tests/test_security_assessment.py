"""Tests for the Security Posture Assessment feature."""
import datetime as dt

from backend import database as db
from backend import ingestion, security_assessment as sa
from backend.agents import orchestrator


def _rich_real_csv():
    """Auth + network data so several categories are assessable."""
    base = dt.datetime(2026, 9, 15, 10, 0, 0)
    lines = ["timestamp,event_type,user,source_ip,destination_ip,port,protocol,"
             "status,authentication_result,bytes"]
    for i in range(14):
        lines.append(f"{(base+dt.timedelta(seconds=i*6)).isoformat()},login,jdoe,"
                     f"203.0.113.66,10.0.0.5,22,tcp,failure,failure,0")
    lines.append(f"{(base+dt.timedelta(seconds=90)).isoformat()},login,jdoe,"
                 f"203.0.113.66,10.0.0.5,22,tcp,success,success,0")
    lines.append(f"{base.isoformat()},connection,,10.0.0.9,10.0.0.5,23,tcp,,,500")
    return "\n".join(lines)


def _prep(dataset="real"):
    s = ingestion.ingest(_rich_real_csv(), "real.csv", dataset)
    orchestrator.run_detection(dataset, s["batch_id"])
    return sa.run_assessment(dataset)


def test_assessment_runs_and_scores():
    b = _prep()
    a = b["assessment"]
    assert a["overall_score"] is not None
    assert a["coverage_total"] == 9
    assert 1 <= a["coverage_assessed"] <= 9
    assert set(a["category_scores"].keys()) == set(sa.CATEGORY_ORDER)


def test_missing_evidence_is_not_assessed():
    b = _prep()
    cats = b["assessment"]["category_scores"]
    # no software/config data exists in this dataset
    assert cats["software_vulnerability"]["status"] == "NOT_ASSESSED"
    assert cats["security_configuration"]["status"] == "NOT_ASSESSED"


def test_not_assessed_never_treated_secure():
    b = _prep()
    for c in b["assessment"]["category_scores"].values():
        if c["status"] == "NOT_ASSESSED":
            assert c["score"] is None   # not 100, not 0


def test_score_is_deterministic():
    b1 = _prep()
    db.reset_dataset("real")
    b2 = _prep()
    assert b1["assessment"]["overall_score"] == b2["assessment"]["overall_score"]
    s1 = {k: v["score"] for k, v in b1["assessment"]["category_scores"].items()}
    s2 = {k: v["score"] for k, v in b2["assessment"]["category_scores"].items()}
    assert s1 == s2


def test_score_components_are_transparent():
    b = _prep()
    for c in b["assessment"]["category_scores"].values():
        assert "checks_performed" in c and "deductions" in c
        for d in c["deductions"]:
            assert "reason" in d and "points" in d


def test_coverage_calculated_correctly():
    b = _prep()
    a = b["assessment"]
    assessed = [c for c in a["category_scores"].values()
                if c["status"] != "NOT_ASSESSED"]
    assert a["coverage_assessed"] == len(assessed)


def test_findings_contain_evidence_no_synthetic():
    b = _prep()
    assert b["findings"]  # this dataset produces findings
    for f in b["findings"]:
        assert f["evidence"], "every finding must reference real evidence"
        assert f["severity"] in ("Critical", "High", "Medium", "Low",
                                 "Informational")


def test_recommendations_correspond_to_findings():
    b = _prep()
    finding_cats = {f["category"] for f in b["findings"]}
    for r in b["recommendations"]:
        assert r["category"] in finding_cats


def test_history_and_dataset_isolation():
    _prep("real")
    _prep("demo")
    real_hist = sa.history("real")
    demo_hist = sa.history("demo")
    assert real_hist and demo_hist
    # resetting demo must not remove real assessments
    db.reset_dataset("demo")
    assert sa.history("real")
    assert not sa.history("demo")
