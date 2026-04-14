#!/usr/bin/env python3
"""Blockchain Verification MCP Server — Immutable audit trails for compliance certifications."""
import json, hashlib, time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("blockchain-verification-mcp")
_LEDGER: list = []

def _hash_block(data: str, prev_hash: str) -> str:
    return hashlib.sha256(f"{prev_hash}{data}{time.time()}".encode()).hexdigest()

@mcp.tool(name="mint_certificate")
async def mint_certificate(organization: str, framework: str, scope: str) -> str:
    prev = _LEDGER[-1]["hash"] if _LEDGER else "0" * 64
    payload = json.dumps({"org": organization, "framework": framework, "scope": scope, "ts": time.time()})
    h = _hash_block(payload, prev)
    block = {"index": len(_LEDGER), "hash": h, "prev": prev, "data": payload}
    _LEDGER.append(block)
    return json.dumps({"certificate_id": h[:16], "block_index": block["index"], "status": "minted"})

@mcp.tool(name="verify_certificate")
async def verify_certificate(certificate_id: str) -> str:
    for block in _LEDGER:
        if block["hash"].startswith(certificate_id):
            return json.dumps({"valid": True, "block_index": block["index"], "data": json.loads(block["data"])})
    return json.dumps({"valid": False, "error": "Certificate not found"})

@mcp.tool(name="audit_trail")
async def audit_trail(organization: str) -> str:
    results = [json.loads(b["data"]) for b in _LEDGER if json.loads(b["data"]).get("org") == organization]
    return json.dumps({"organization": organization, "events": results})

@mcp.tool(name="integrity_check")
async def integrity_check() -> str:
    for i in range(1, len(_LEDGER)):
        if _LEDGER[i]["prev"] != _LEDGER[i-1]["hash"]:
            return json.dumps({"valid": False, "broken_at_index": i})
    return json.dumps({"valid": True, "blocks": len(_LEDGER)})

if __name__ == "__main__":
    mcp.run()
