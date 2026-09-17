"""Incident context assembled by the orchestrator and consumed by agents."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IncidentContext:
    incident_id: str
    dataset: str
    attack_type: str
    severity: str
    detection_reason: str
    confidence: float                       # detection confidence (0..1)
    anomaly_score: float
    events: list[dict] = field(default_factory=list)   # normalized event rows
    source_ips: set = field(default_factory=set)
    destination_ips: set = field(default_factory=set)
    users: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    injection_signals: list[str] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)
