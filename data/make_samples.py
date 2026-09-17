"""Generate SYNTHETIC sample security-event files for the Real Data workflow.

These are synthetic events for demonstration / testing the upload pipeline —
NOT real company data. Run:  python data/make_samples.py
"""
import csv
import datetime as dt
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIELDS = ["timestamp", "event_type", "user", "host", "source_ip",
          "destination_ip", "port", "protocol", "action", "status",
          "severity", "process", "command", "bytes", "authentication_result"]


def row(ts, **kw):
    r = {f: "" for f in FIELDS}
    r["timestamp"] = ts.isoformat()
    r.update(kw)
    return r


def build():
    rows = []
    base = dt.datetime(2026, 9, 15, 10, 31, 0)

    # 1) Brute force -> success (credential compromise) from a known-bad IP
    for i in range(14):
        rows.append(row(base + dt.timedelta(seconds=i * 6), event_type="login",
                        user="jdoe", host="WKS-201", source_ip="203.0.113.66",
                        protocol="ssh", action="logon", status="failure",
                        severity="medium", authentication_result="failure"))
    rows.append(row(base + dt.timedelta(seconds=90), event_type="login",
                    user="jdoe", host="WKS-201", source_ip="203.0.113.66",
                    action="logon", status="success", severity="high",
                    authentication_result="success"))
    rows.append(row(base + dt.timedelta(seconds=110), event_type="process",
                    user="jdoe", host="WKS-201", process="cmd.exe",
                    command="whoami /priv", severity="high"))

    # 2) Port scan from another bad IP
    pbase = base + dt.timedelta(minutes=20)
    for i, p in enumerate(random.sample(range(20, 9000), 24)):
        rows.append(row(pbase + dt.timedelta(seconds=i * 2), event_type="connection",
                        host="DB-PROD-1", source_ip="45.155.205.233",
                        destination_ip="10.0.0.15", port=p, protocol="tcp",
                        action="syn", status="blocked", severity="low"))

    # 3) Suspicious PowerShell on a workstation
    rows.append(row(base + dt.timedelta(minutes=40), event_type="process",
                    user="asmith", host="WKS-330", process="powershell.exe",
                    command="powershell -nop -w hidden -enc SQBFAFgAKAB…",
                    severity="high"))

    # 4) Data exfiltration to a malicious destination
    ebase = base + dt.timedelta(minutes=55)
    for i in range(4):
        rows.append(row(ebase + dt.timedelta(seconds=i * 20), event_type="exfiltration",
                        user="svc_backup", host="FIN-APP-2", source_ip="10.0.0.15",
                        destination_ip="198.51.100.199", port=443, protocol="https",
                        action="upload", bytes=random.randint(8_000_000, 30_000_000),
                        severity="high"))

    # 5) Normal/benign background noise (so detection is not trivially everything)
    nbase = base - dt.timedelta(minutes=30)
    for i in range(40):
        rows.append(row(nbase + dt.timedelta(seconds=i * 40), event_type="login",
                        user=random.choice(["mkhan", "rlee", "asmith"]),
                        host=random.choice(["WKS-118", "WKS-201"]),
                        source_ip="10.0.0." + str(random.randint(20, 60)),
                        action="logon", status="success", severity="low",
                        authentication_result="success"))

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def main():
    rows = build()
    with open(HERE / "sample_events.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(HERE / "sample_events.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(f"Wrote {len(rows)} synthetic events to sample_events.csv / .json")


if __name__ == "__main__":
    main()
