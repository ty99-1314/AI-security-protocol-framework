#!/usr/bin/env python3
"""Runnable defensive examples for authorization and message integrity."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

# Explicit demo policy: role -> allowed (action, resource) pairs.
POLICY = {
    "support": {("read", "ticket"), ("reply", "ticket")},
    "finance": {("read", "invoice"), ("export", "invoice")},
}


def authorize(role: str, action: str, resource: str) -> bool:
    """Default-deny role-based authorization check."""
    return (action, resource) in POLICY.get(role, set())


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Produce stable bytes for signing; reject non-standard NaN/Infinity."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign_message(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Return a JSON-compatible message with an HMAC-SHA256 integrity tag.

    This provides integrity/authentication to holders of the shared key, not
    confidentiality. Use TLS or authenticated encryption to protect traffic.
    """
    if not key:
        raise ValueError("HMAC key must not be empty")
    signature = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}


def verify_message(envelope: dict[str, Any], key: bytes) -> bool:
    """Verify an envelope without raising for malformed/untrusted input."""
    if not key or not isinstance(envelope, dict):
        return False
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    try:
        expected = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(signature, expected)


def main() -> None:
    print("Authorization examples (default deny):")
    for role, action, resource in (
        ("support", "read", "ticket"),
        ("support", "delete", "ticket"),
        ("unknown", "read", "ticket"),
    ):
        print(f"  {role} {action} {resource}: {'ALLOW' if authorize(role, action, resource) else 'DENY'}")

    key = b"demo-only-change-this-key"
    envelope = sign_message({"agent_id": "support-bot-7", "action": "read", "resource": "ticket"}, key)
    print("\nMessage integrity examples (HMAC-SHA256; not encryption):")
    print(f"  original verifies: {verify_message(envelope, key)}")
    envelope["payload"]["action"] = "delete"
    print(f"  modified payload verifies: {verify_message(envelope, key)}")


if __name__ == "__main__":
    main()
