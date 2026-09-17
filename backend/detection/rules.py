"""Rule-based threat detection.

Each detector consumes a list of normalized event rows (dicts that include the
DB ``id``) and emits :class:`Detection` objects. A Detection is a *correlated*
group of events with an explanation, so it maps naturally onto one incident.

Every Detection carries a human-readable ``reason`` so the system can always
explain *why* something was flagged.
"""
from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from dataclasses import dataclass, field

from . import mitre

# --- Tunable thresholds ---------------------------------------------------- #
BRUTE_FORCE_MIN_FAILS = 6          # failed logins from one src ip
BRUTE_FORCE_WINDOW_S = 300          # within this window (seconds)
PORT_SCAN_MIN_PORTS = 10            # distinct ports from one src ip
PORT_SCAN_WINDOW_S = 120
LATERAL_MIN_HOSTS = 3              # distinct hosts one user authenticates to
LATERAL_WINDOW_S = 600
EXFIL_MIN_BYTES = 5_000_000        # single outbound transfer considered large
EXFIL_TOTAL_BYTES = 20_000_000     # aggregate outbound to one dest

SUSPICIOUS_PORTS = {23, 445, 3389, 4444, 1337, 31337, 5555, 6667, 8888, 9001}
POWERSHELL_MARKERS = [
    "-enc", "-encodedcommand", "downloadstring", "iex", "invoke-expression",
    "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "frombase64string",
    "bypass", "invoke-webrequest", "net.webclient", "certutil -urlcache",
]
PRIVESC_MARKERS = [
    "net localgroup administrators", "net group \"domain admins\"", "whoami /priv",
    "sudo su", "runas", "getsystem", "sedebugprivilege", "add-member administrators",
]
MALWARE_PROCESSES = {"mimikatz.exe", "psexec.exe", "cobaltstrike", "nc.exe",
                     "ncat.exe", "wce.exe"}


def _parse_ts(value) -> _dt.datetime:
    if not value:
        return _dt.datetime.min
    s = str(value)
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return _dt.datetime.min


@dataclass
class Detection:
    attack_type: str
    severity: str
    confidence: float           # 0..1
    reason: str
    event_ids: list[int] = field(default_factory=list)
    source_ips: set = field(default_factory=set)
    users: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    destination_ips: set = field(default_factory=set)
    detector: str = "rule"
    anomaly_score: float = 0.0
    correlation_key: str = ""
    extra: dict = field(default_factory=dict)

    def mitre(self) -> list[dict]:
        return mitre.techniques_for(self.attack_type, self.reason, self.confidence)


def _is_failed_login(e: dict) -> bool:
    et = (e.get("event_type") or "").lower()
    ar = (e.get("authentication_result") or "").lower()
    st = (e.get("status") or "").lower()
    if ar == "failure":
        return True
    if "login" in et or "logon" in et or "auth" in et:
        return st in ("failure", "failed", "denied") or ar == "failure"
    return False


def _is_success_login(e: dict) -> bool:
    et = (e.get("event_type") or "").lower()
    ar = (e.get("authentication_result") or "").lower()
    st = (e.get("status") or "").lower()
    if ar == "success":
        return True
    if "login" in et or "logon" in et or "auth" in et:
        return st in ("success", "succeeded", "ok", "allowed")
    return False


# --------------------------------------------------------------------------- #
# Individual detectors
# --------------------------------------------------------------------------- #
def detect_brute_force(events: list[dict]) -> list[Detection]:
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if _is_failed_login(e) and e.get("source_ip"):
            by_ip[e["source_ip"]].append(e)

    detections = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: _parse_ts(e.get("timestamp")))
        # sliding window
        best_window: list[dict] = []
        for i, anchor in enumerate(evs):
            t0 = _parse_ts(anchor.get("timestamp"))
            window = [x for x in evs[i:]
                      if (_parse_ts(x.get("timestamp")) - t0).total_seconds()
                      <= BRUTE_FORCE_WINDOW_S]
            if len(window) > len(best_window):
                best_window = window
        if len(best_window) >= BRUTE_FORCE_MIN_FAILS:
            span = (_parse_ts(best_window[-1]["timestamp"])
                    - _parse_ts(best_window[0]["timestamp"])).total_seconds()
            users = {x.get("user") for x in best_window if x.get("user")}
            hosts = {x.get("host") for x in best_window if x.get("host")}
            n = len(best_window)
            conf = min(0.98, 0.55 + 0.03 * (n - BRUTE_FORCE_MIN_FAILS))
            det = Detection(
                attack_type="brute_force",
                severity="High" if n >= 12 else "Medium",
                confidence=round(conf, 2),
                reason=(f"{n} failed login attempts from source IP {ip} "
                        f"within {int(span)}s "
                        f"(threshold {BRUTE_FORCE_MIN_FAILS}/{BRUTE_FORCE_WINDOW_S}s)."),
                event_ids=[x["id"] for x in best_window],
                source_ips={ip}, users=users, hosts=hosts,
                correlation_key=f"bruteforce:{ip}",
            )
            detections.append(det)
    return detections


def detect_credential_compromise(events: list[dict],
                                 brute: list[Detection]) -> list[Detection]:
    """A brute-force IP followed by a SUCCESSFUL login => credential compromise."""
    detections = []
    for d in brute:
        ip = next(iter(d.source_ips))
        last_fail = max(
            (_parse_ts(e.get("timestamp"))
             for e in events if e.get("id") in set(d.event_ids)),
            default=_dt.datetime.min,
        )
        successes = [
            e for e in events
            if e.get("source_ip") == ip and _is_success_login(e)
            and _parse_ts(e.get("timestamp")) >= last_fail - _dt.timedelta(seconds=BRUTE_FORCE_WINDOW_S)
        ]
        if successes:
            succ = min(successes, key=lambda e: _parse_ts(e.get("timestamp")))
            users = set(d.users) | ({succ.get("user")} if succ.get("user") else set())
            hosts = set(d.hosts) | ({succ.get("host")} if succ.get("host") else set())
            det = Detection(
                attack_type="credential_compromise",
                severity="Critical",
                confidence=round(min(0.97, d.confidence + 0.05), 2),
                reason=(f"Successful login from {ip} (user "
                        f"{succ.get('user') or 'unknown'}) after "
                        f"{len(d.event_ids)} failed attempts — likely credential "
                        f"compromise."),
                event_ids=d.event_ids + [succ["id"]],
                source_ips={ip}, users=users, hosts=hosts,
                correlation_key=f"bruteforce:{ip}",  # same key -> supersedes brute
                extra={"supersedes": "brute_force"},
            )
            detections.append(det)
    return detections


def detect_port_scan(events: list[dict]) -> list[Detection]:
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        et = (e.get("event_type") or "").lower()
        if e.get("source_ip") and (e.get("port") is not None
                                   or "connection" in et or "network" in et
                                   or "scan" in et):
            by_ip[e["source_ip"]].append(e)

    detections = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: _parse_ts(e.get("timestamp")))
        ports = {e.get("port") for e in evs if e.get("port") is not None}
        span = ((_parse_ts(evs[-1]["timestamp"]) - _parse_ts(evs[0]["timestamp"]))
                .total_seconds() if len(evs) > 1 else 0)
        if len(ports) >= PORT_SCAN_MIN_PORTS and span <= max(PORT_SCAN_WINDOW_S * 4, 1):
            conf = min(0.95, 0.5 + 0.02 * (len(ports) - PORT_SCAN_MIN_PORTS))
            hosts = {e.get("host") for e in evs if e.get("host")}
            det = Detection(
                attack_type="port_scan",
                severity="Medium",
                confidence=round(conf, 2),
                reason=(f"{len(ports)} distinct ports probed from {ip} "
                        f"within {int(span)}s — network service discovery / "
                        f"port scan."),
                event_ids=[e["id"] for e in evs],
                source_ips={ip}, hosts=hosts,
                destination_ips={e.get("destination_ip") for e in evs
                                 if e.get("destination_ip")},
                correlation_key=f"portscan:{ip}",
                extra={"ports": sorted(p for p in ports if p is not None)[:50]},
            )
            detections.append(det)
    return detections


def detect_suspicious_powershell(events: list[dict]) -> list[Detection]:
    detections = []
    for e in events:
        blob = f"{e.get('process') or ''} {e.get('command') or ''}".lower()
        if "powershell" not in blob and "pwsh" not in blob and "cmd.exe" not in blob:
            continue
        markers = [m for m in POWERSHELL_MARKERS if m in blob]
        if markers:
            conf = min(0.95, 0.55 + 0.08 * len(markers))
            det = Detection(
                attack_type="suspicious_powershell",
                severity="High",
                confidence=round(conf, 2),
                reason=("Suspicious script execution detected "
                        f"(indicators: {', '.join(markers[:4])})."),
                event_ids=[e["id"]],
                source_ips={e.get("source_ip")} if e.get("source_ip") else set(),
                users={e.get("user")} if e.get("user") else set(),
                hosts={e.get("host")} if e.get("host") else set(),
                correlation_key=f"powershell:{e.get('host')}:{e.get('user')}",
                extra={"markers": markers},
            )
            detections.append(det)
    return detections


def detect_privilege_escalation(events: list[dict]) -> list[Detection]:
    detections = []
    for e in events:
        et = (e.get("event_type") or "").lower()
        blob = f"{e.get('command') or ''} {e.get('action') or ''}".lower()
        markers = [m for m in PRIVESC_MARKERS if m in blob]
        if "privilege" in et or "escalat" in et or markers:
            reason = ("Privilege escalation indicator"
                      + (f" ({', '.join(markers[:3])})" if markers
                         else f" (event_type={e.get('event_type')})") + ".")
            det = Detection(
                attack_type="privilege_escalation",
                severity="High",
                confidence=0.72 if markers else 0.6,
                reason=reason,
                event_ids=[e["id"]],
                source_ips={e.get("source_ip")} if e.get("source_ip") else set(),
                users={e.get("user")} if e.get("user") else set(),
                hosts={e.get("host")} if e.get("host") else set(),
                correlation_key=f"privesc:{e.get('host')}:{e.get('user')}",
            )
            detections.append(det)
    return detections


def detect_data_exfiltration(events: list[dict]) -> list[Detection]:
    detections = []
    # single large transfer
    for e in events:
        et = (e.get("event_type") or "").lower()
        b = e.get("bytes") or 0
        if "exfil" in et or (b and b >= EXFIL_MIN_BYTES):
            det = Detection(
                attack_type="data_exfiltration",
                severity="Critical" if b >= EXFIL_MIN_BYTES * 4 else "High",
                confidence=0.7 if b else 0.6,
                reason=(f"Large / suspicious outbound transfer "
                        f"({b:,} bytes) to {e.get('destination_ip') or 'external'}"
                        if b else "Data exfiltration event flagged."),
                event_ids=[e["id"]],
                source_ips={e.get("source_ip")} if e.get("source_ip") else set(),
                users={e.get("user")} if e.get("user") else set(),
                hosts={e.get("host")} if e.get("host") else set(),
                destination_ips={e.get("destination_ip")}
                if e.get("destination_ip") else set(),
                correlation_key=f"exfil:{e.get('host')}:{e.get('destination_ip')}",
            )
            detections.append(det)
    return detections


def detect_lateral_movement(events: list[dict]) -> list[Detection]:
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        et = (e.get("event_type") or "").lower()
        if e.get("user") and (_is_success_login(e) or "remote" in et
                              or "lateral" in et or "rdp" in et or "smb" in et):
            by_user[e["user"]].append(e)
    detections = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: _parse_ts(e.get("timestamp")))
        hosts = {e.get("host") for e in evs if e.get("host")}
        span = ((_parse_ts(evs[-1]["timestamp"]) - _parse_ts(evs[0]["timestamp"]))
                .total_seconds() if len(evs) > 1 else 0)
        if len(hosts) >= LATERAL_MIN_HOSTS and span <= LATERAL_WINDOW_S * 3:
            det = Detection(
                attack_type="lateral_movement",
                severity="High",
                confidence=round(min(0.9, 0.5 + 0.1 * (len(hosts) - LATERAL_MIN_HOSTS)), 2),
                reason=(f"User '{user}' authenticated to {len(hosts)} hosts "
                        f"within {int(span)}s — possible lateral movement."),
                event_ids=[e["id"] for e in evs],
                users={user}, hosts=hosts,
                source_ips={e.get("source_ip") for e in evs if e.get("source_ip")},
                correlation_key=f"lateral:{user}",
            )
            detections.append(det)
    return detections


def detect_malware(events: list[dict]) -> list[Detection]:
    detections = []
    for e in events:
        et = (e.get("event_type") or "").lower()
        proc = (e.get("process") or "").lower()
        hit = "malware" in et or any(m in proc for m in MALWARE_PROCESSES)
        if hit:
            det = Detection(
                attack_type="malware_execution",
                severity="Critical",
                confidence=0.8,
                reason=(f"Known-malicious tool / malware indicator: "
                        f"{e.get('process') or e.get('event_type')}."),
                event_ids=[e["id"]],
                source_ips={e.get("source_ip")} if e.get("source_ip") else set(),
                users={e.get("user")} if e.get("user") else set(),
                hosts={e.get("host")} if e.get("host") else set(),
                correlation_key=f"malware:{e.get('host')}",
            )
            detections.append(det)
    return detections


def detect_suspicious_ports(events: list[dict]) -> list[Detection]:
    by_key: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("port") in SUSPICIOUS_PORTS and _is_success_login(e) is False:
            key = f"{e.get('source_ip')}->{e.get('destination_ip')}:{e.get('port')}"
            by_key[key].append(e)
    detections = []
    for key, evs in by_key.items():
        ports = sorted({e.get("port") for e in evs})
        det = Detection(
            attack_type="anomalous_behaviour",
            severity="Medium",
            confidence=0.55,
            reason=(f"Connection(s) to suspicious port(s) {ports} "
                    f"from {evs[0].get('source_ip')}."),
            event_ids=[e["id"] for e in evs],
            source_ips={e.get("source_ip") for e in evs if e.get("source_ip")},
            hosts={e.get("host") for e in evs if e.get("host")},
            destination_ips={e.get("destination_ip") for e in evs
                             if e.get("destination_ip")},
            correlation_key=f"suspport:{key}",
        )
        detections.append(det)
    return detections


ALL_DETECTORS = [
    detect_port_scan,
    detect_suspicious_powershell,
    detect_privilege_escalation,
    detect_data_exfiltration,
    detect_lateral_movement,
    detect_malware,
    detect_suspicious_ports,
]


def run_rules(events: list[dict]) -> list[Detection]:
    """Run every rule detector and reconcile overlapping detections."""
    brute = detect_brute_force(events)
    cred = detect_credential_compromise(events, brute)
    detections: list[Detection] = []
    detections.extend(cred)
    # drop brute-force detections superseded by a credential-compromise finding
    superseded_keys = {d.correlation_key for d in cred}
    detections.extend(d for d in brute if d.correlation_key not in superseded_keys)
    for detector in ALL_DETECTORS:
        detections.extend(detector(events))
    return detections
