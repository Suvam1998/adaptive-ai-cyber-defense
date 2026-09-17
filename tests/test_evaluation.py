"""Tests for the Evaluation module (metrics from real labels; no fabrication)."""
import datetime as dt

from backend import database as db
from backend import evaluation, ingestion
from backend.agents import orchestrator


def _labelled_cic_csv():
    base = dt.datetime(2026, 9, 15, 10, 0, 0)
    lines = ["Timestamp,Source IP,Destination IP,Dst Port,Protocol,"
             "TotLen Fwd Pkts,Label"]
    # 20 port-scan flows from one source (attack)
    for i in range(20):
        lines.append(f"{(base+dt.timedelta(seconds=i)).isoformat()},172.16.0.9,"
                     f"10.0.0.5,{1000+i},6,120,PortScan")
    # 25 benign flows
    for i in range(25):
        lines.append(f"{(base+dt.timedelta(seconds=i)).isoformat()},10.0.0."
                     f"{20+i%5},10.0.0.5,443,6,3000,BENIGN")
    return "\n".join(lines)


def test_metrics_computed_from_labels():
    s = ingestion.ingest(_labelled_cic_csv(), "cic.csv", "real")
    orchestrator.run_detection("real", s["batch_id"])
    r = evaluation.evaluate("real")
    assert r["labelled_available"] is True
    assert r["attack_types"].get("PortScan") == 20
    assert r["attack_types"].get("BENIGN") == 25
    p = r["proposed"]
    # confusion counts are real integers summing to the labelled count
    assert (p["true_positives"] + p["false_positives"] + p["true_negatives"]
            + p["false_negatives"]) == 45
    assert isinstance(p["precision"], float)


def test_benign_labels_are_not_ground_truth_attacks():
    assert evaluation._is_attack_label("PortScan") is True
    assert evaluation._is_attack_label("BENIGN") is False
    assert evaluation._is_attack_label("") is False
    assert evaluation._is_attack_label(None) is False


def test_not_available_without_labels():
    ingestion.ingest("timestamp,event_type,source_ip\n"
                     "2026-09-15T10:00:00,login,10.0.0.1", "nolabel.csv", "real")
    r = evaluation.evaluate("real")
    assert r["labelled_available"] is False
    assert r["proposed"]["precision"] == "Not available"
    assert r["baseline"]["recall"] == "Not available"


def test_baseline_and_proposed_both_reported():
    s = ingestion.ingest(_labelled_cic_csv(), "cic.csv", "real")
    orchestrator.run_detection("real", s["batch_id"])
    r = evaluation.evaluate("real")
    assert r["baseline"] is not None and r["proposed"] is not None
    assert "rule_detection_ms" in r["timings"]
