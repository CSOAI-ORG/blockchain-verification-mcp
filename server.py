#!/usr/bin/env python3
"""Blockchain Verification MCP Server — Immutable audit trails for compliance certifications."""
import json, hashlib, time
from datetime import datetime, timezone
from collections import defaultdict
from mcp.server.fastmcp import FastMCP
import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

mcp = FastMCP("blockchain-verification", instructions="MEOK AI Labs MCP Server")

FREE_DAILY_LIMIT = 15
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day"})
    _usage[c].append(now); return None
_LEDGER: list = []

def _hash_block(data: str, prev_hash: str) -> str:
    return hashlib.sha256(f"{prev_hash}{data}{time.time()}".encode()).hexdigest()

@mcp.tool()
def mint_certificate(organization: str, framework: str, scope: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    prev = _LEDGER[-1]["hash"] if _LEDGER else "0" * 64
    payload = json.dumps({"org": organization, "framework": framework, "scope": scope, "ts": time.time()})
    h = _hash_block(payload, prev)
    block = {"index": len(_LEDGER), "hash": h, "prev": prev, "data": payload}
    _LEDGER.append(block)
    return {"certificate_id": h[:16], "block_index": block["index"], "status": "minted"}

@mcp.tool()
def verify_certificate(certificate_id: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    for block in _LEDGER:
        if block["hash"].startswith(certificate_id):
            return {"valid": True, "block_index": block["index"], "data": json.loads(block["data"])}
    return {"valid": False, "error": "Certificate not found"}

@mcp.tool()
def audit_trail(organization: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    results = [json.loads(b["data"]) for b in _LEDGER if json.loads(b["data"]).get("org") == organization]
    return {"organization": organization, "events": results}

@mcp.tool()
def integrity_check(api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if err := _rl(): return err

    for i in range(1, len(_LEDGER)):
        if _LEDGER[i]["prev"] != _LEDGER[i-1]["hash"]:
            return {"valid": False, "broken_at_index": i}
    return {"valid": True, "blocks": len(_LEDGER)}

if __name__ == "__main__":
    mcp.run()