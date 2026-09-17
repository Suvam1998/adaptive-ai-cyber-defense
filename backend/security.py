"""Safeguards for the AI system itself.

Core principle: **raw log content is DATA, never an instruction.** Nothing read
from an event, upload, or stored memory is ever executed or interpreted as a
command to the system. This module centralises the defensive helpers:

* ``sanitize_text``  - neutralise control chars / injection markers for display
* ``scan_injection`` - flag events whose text tries to smuggle instructions
* ``safe_filename``  - reject path traversal in uploads
* memory trust is enforced in ``agents/memory_agent.py`` (revoked != used)
"""
from __future__ import annotations

import re

# Patterns that commonly appear in prompt-injection / instruction-smuggling
# attempts embedded inside otherwise-normal log text. We only FLAG these (as a
# security signal / evidence); we never act on them.
INJECTION_PATTERNS = [
    r"ignore (all|previous|prior) instructions",
    r"disregard (the )?(above|previous|system)",
    r"you are now",
    r"system prompt",
    r"</?(system|assistant|user)>",
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"os\.system",
    r"subprocess",
    r"rm\s+-rf",
    r"drop\s+table",
    r"; *delete +from",
    r"assistant:\s",
    r"<\|.*?\|>",
]
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value, max_len: int = 2000) -> str:
    """Return a safe-for-display string: strip control chars, cap length.

    This never evaluates the content. It is purely presentational hardening so
    injected escape sequences / control characters cannot corrupt logs or the
    terminal / browser rendering.
    """
    if value is None:
        return ""
    text = str(value)
    text = _CONTROL_RE.sub(" ", text)
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


def scan_injection(text) -> list[str]:
    """Return the list of injection markers found in ``text`` (may be empty)."""
    if not text:
        return []
    found = []
    for m in _INJECTION_RE.finditer(str(text)):
        found.append(m.group(0))
    # de-dup preserving order
    seen, out = set(), []
    for f in found:
        k = f.lower()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def event_injection_signals(event: dict) -> list[str]:
    """Scan the free-text fields of a normalized event for injection markers."""
    signals = []
    for field in ("command", "raw_event", "user", "process", "action"):
        signals.extend(scan_injection(event.get(field)))
    seen, out = set(), []
    for s in signals:
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(name: str) -> str:
    """Strip any directory component and unsafe chars from an upload filename."""
    name = (name or "upload").replace("\\", "/").split("/")[-1]
    name = _SAFE_NAME_RE.sub("_", name)
    return name[:120] or "upload"
