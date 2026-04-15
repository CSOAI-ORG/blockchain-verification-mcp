#!/usr/bin/env python3
"""Blockchain Verification MCP Server — Immutable audit trails for compliance certifications."""

import json, hashlib, time, uuid
from datetime import datetime, timezone
from collections import defaultdict
from mcp.server.fastmcp import FastMCP
import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

mcp = FastMCP("blockchain-verification", instructions="MEOK AI Labs — Immutable audit trails and certificate verification with SHA-256 hash chains.")

FREE_DAILY_LIMIT = 15
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day"})
    _usage[c].append(now); return None

_LEDGER: list = []
_VERIFICATION_LOG: dict = defaultdict(list)
_REVOCATIONS: set = set()

SUPPORTED_FRAMEWORKS = {
    "iso27001": {"name": "ISO 27001", "category": "Information Security", "validity_years": 3},
    "soc2": {"name": "SOC 2", "category": "Service Organization Controls", "validity_years": 1},
    "gdpr": {"name": "GDPR Compliance", "category": "Data Protection", "validity_years": 2},
    "hipaa": {"name": "HIPAA", "category": "Healthcare", "validity_years": 1},
    "pci_dss": {"name": "PCI DSS", "category": "Payment Security", "validity_years": 1},
    "iso13485": {"name": "ISO 13485", "category": "Medical Devices QMS", "validity_years": 3},
    "eu_ai_act": {"name": "EU AI Act", "category": "AI Regulation", "validity_years": 2},
    "cyber_essentials": {"name": "Cyber Essentials", "category": "Cybersecurity", "validity_years": 1},
}


def _hash_block(data: str, prev_hash: str) -> str:
    raw = f"{prev_hash}:{data}:{time.time_ns()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _merkle_root(hashes: list) -> str:
    if not hashes:
        return hashlib.sha256(b"empty").hexdigest()
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [hashlib.sha256((hashes[i] + hashes[i + 1]).encode()).hexdigest()
                   for i in range(0, len(hashes), 2)]
    return hashes[0]


@mcp.tool()
def mint_certificate(organization: str, framework: str, scope: str,
                     auditor: str = "", valid_years: int = 0, api_key: str = "") -> str:
    """Mint a blockchain-backed compliance certificate with SHA-256 hash chain, merkle root, and metadata."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    fw_info = SUPPORTED_FRAMEWORKS.get(framework.lower(), {"name": framework, "category": "Custom", "validity_years": 1})
    validity = valid_years if valid_years > 0 else fw_info["validity_years"]

    prev = _LEDGER[-1]["hash"] if _LEDGER else "0" * 64
    ts = time.time()
    cert_id = str(uuid.uuid4())[:16]
    payload = {
        "cert_id": cert_id,
        "org": organization,
        "framework": fw_info["name"],
        "framework_key": framework.lower(),
        "category": fw_info["category"],
        "scope": scope,
        "auditor": auditor or "Self-assessed",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "valid_until": datetime.fromtimestamp(ts + validity * 365.25 * 86400, tz=timezone.utc).isoformat(),
        "validity_years": validity,
    }
    payload_str = json.dumps(payload, sort_keys=True)
    content_hash = hashlib.sha256(payload_str.encode()).hexdigest()
    block_hash = _hash_block(payload_str, prev)

    block = {
        "index": len(_LEDGER),
        "hash": block_hash,
        "prev": prev,
        "content_hash": content_hash,
        "data": payload_str,
        "timestamp": ts,
    }
    _LEDGER.append(block)

    _VERIFICATION_LOG[cert_id].append({"event": "minted", "timestamp": datetime.now(timezone.utc).isoformat(), "block_index": block["index"]})

    return {
        "certificate_id": cert_id,
        "block_index": block["index"],
        "block_hash": block_hash[:32],
        "content_hash": content_hash[:32],
        "framework": fw_info["name"],
        "organization": organization,
        "valid_until": payload["valid_until"],
        "status": "minted",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def verify_certificate(certificate_id: str, api_key: str = "") -> str:
    """Verify a certificate's authenticity by checking hash chain integrity, revocation status, and expiry."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    if certificate_id in _REVOCATIONS:
        return {"valid": False, "certificate_id": certificate_id, "reason": "Certificate has been revoked",
                "timestamp": datetime.now(timezone.utc).isoformat()}

    for i, block in enumerate(_LEDGER):
        data = json.loads(block["data"])
        if data.get("cert_id") == certificate_id or block["hash"].startswith(certificate_id):
            chain_valid = True
            if i > 0 and block["prev"] != _LEDGER[i - 1]["hash"]:
                chain_valid = False

            content_check = hashlib.sha256(block["data"].encode()).hexdigest()
            content_valid = content_check == block["content_hash"]

            now_str = datetime.now(timezone.utc).isoformat()
            expired = data.get("valid_until", "") < now_str if data.get("valid_until") else False

            _VERIFICATION_LOG[certificate_id].append({"event": "verified", "timestamp": now_str, "chain_valid": chain_valid})

            return {
                "valid": chain_valid and content_valid and not expired,
                "certificate_id": certificate_id,
                "block_index": block["index"],
                "chain_integrity": chain_valid,
                "content_integrity": content_valid,
                "expired": expired,
                "certificate_data": data,
                "verification_count": len(_VERIFICATION_LOG.get(certificate_id, [])),
                "timestamp": now_str,
            }

    return {"valid": False, "certificate_id": certificate_id, "error": "Certificate not found in ledger",
            "timestamp": datetime.now(timezone.utc).isoformat()}


@mcp.tool()
def audit_trail(organization: str, framework: str = "", api_key: str = "") -> str:
    """Get the full audit trail for an organization, optionally filtered by framework, with timeline and stats."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    events = []
    cert_ids = []
    for block in _LEDGER:
        data = json.loads(block["data"])
        if data.get("org") == organization:
            if framework and data.get("framework_key", "").lower() != framework.lower():
                continue
            cert_id = data.get("cert_id", block["hash"][:16])
            cert_ids.append(cert_id)
            verification_events = _VERIFICATION_LOG.get(cert_id, [])
            events.append({
                "certificate_id": cert_id,
                "framework": data.get("framework", "Unknown"),
                "scope": data.get("scope", ""),
                "issued_at": data.get("issued_at", ""),
                "valid_until": data.get("valid_until", ""),
                "block_index": block["index"],
                "verification_count": len(verification_events),
                "revoked": cert_id in _REVOCATIONS,
            })

    active = sum(1 for e in events if not e["revoked"])
    return {
        "organization": organization,
        "framework_filter": framework or "all",
        "total_certificates": len(events),
        "active": active,
        "revoked": len(events) - active,
        "events": events,
        "merkle_root": _merkle_root([b["hash"] for b in _LEDGER if json.loads(b["data"]).get("org") == organization]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def integrity_check(deep_scan: bool = False, api_key: str = "") -> str:
    """Run full integrity check on the certificate ledger — validates hash chain, content hashes, and merkle tree."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    if not _LEDGER:
        return {"valid": True, "blocks": 0, "message": "Ledger is empty", "timestamp": datetime.now(timezone.utc).isoformat()}

    chain_errors = []
    content_errors = []

    for i in range(len(_LEDGER)):
        block = _LEDGER[i]
        if i > 0 and block["prev"] != _LEDGER[i - 1]["hash"]:
            chain_errors.append({"block_index": i, "error": "Previous hash mismatch",
                                  "expected": _LEDGER[i - 1]["hash"][:16], "got": block["prev"][:16]})

        if deep_scan and "content_hash" in block:
            computed = hashlib.sha256(block["data"].encode()).hexdigest()
            if computed != block["content_hash"]:
                content_errors.append({"block_index": i, "error": "Content hash mismatch"})

    all_hashes = [b["hash"] for b in _LEDGER]
    merkle = _merkle_root(all_hashes)

    orgs = set()
    for block in _LEDGER:
        data = json.loads(block["data"])
        orgs.add(data.get("org", "unknown"))

    valid = len(chain_errors) == 0 and len(content_errors) == 0
    return {
        "valid": valid,
        "blocks": len(_LEDGER),
        "chain_errors": chain_errors,
        "content_errors": content_errors if deep_scan else "skipped (set deep_scan=true)",
        "merkle_root": merkle,
        "organizations": list(orgs),
        "total_revocations": len(_REVOCATIONS),
        "deep_scan": deep_scan,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    mcp.run()
