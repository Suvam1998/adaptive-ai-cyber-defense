"""Lightweight MITRE ATT&CK technique mapping.

Techniques are only attached to an incident when the detection that produced
them was actually observed in the evidence (see rules.py / anomaly.py). We do
not claim a technique without supporting evidence.
"""
from __future__ import annotations

# attack_type -> list of technique dicts
ATTACK_TECHNIQUES: dict[str, list[dict]] = {
    "brute_force": [
        {"id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access"},
    ],
    "credential_compromise": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "port_scan": [
        {"id": "T1046", "name": "Network Service Discovery",
         "tactic": "Discovery"},
    ],
    "suspicious_powershell": [
        {"id": "T1059.001", "name": "PowerShell",
         "tactic": "Execution"},
        {"id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic": "Execution"},
    ],
    "privilege_escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation",
         "tactic": "Privilege Escalation"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"},
    ],
    "data_exfiltration": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
         "tactic": "Exfiltration"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel",
         "tactic": "Exfiltration"},
    ],
    "lateral_movement": [
        {"id": "T1021", "name": "Remote Services",
         "tactic": "Lateral Movement"},
    ],
    "malware_execution": [
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
        {"id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic": "Execution"},
    ],
    "anomalous_behaviour": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
}


def techniques_for(attack_type: str, evidence_note: str = "",
                   confidence: float = 0.5) -> list[dict]:
    out = []
    for t in ATTACK_TECHNIQUES.get(attack_type, []):
        item = dict(t)
        item["evidence"] = evidence_note
        item["confidence"] = round(confidence, 2)
        out.append(item)
    return out
