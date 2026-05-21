<div align="center">

# Blockchain Verification MCP

**MCP server for blockchain verification mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-blockchain-verification-mcp)](https://pypi.org/project/meok-blockchain-verification-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Blockchain Verification MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `mint_certificate` | Mint a blockchain-backed compliance certificate with SHA-256 hash chain, merkle  |
| `verify_certificate` | Verify a certificate's authenticity by checking hash chain integrity, revocation |
| `audit_trail` | Get the full audit trail for an organization, optionally filtered by framework,  |
| `integrity_check` | Run full integrity check on the certificate ledger — validates hash chain, conte |

## Installation

```bash
pip install meok-blockchain-verification-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blockchain-verification": {
      "command": "python",
      "args": ["-m", "meok_blockchain_verification_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

<!-- meok-moat-footer-v1 -->
---

## Pairs with MEOK Governance Suite

Build something that touches users? You need compliance. MEOK ships 38 governance MCPs that drop in alongside this tool — EU AI Act, DORA, NIS2, CRA, GDPR, ISO 42001, FDA SaMD, MDR, Basel, MiFID II, MiCA, COPPA, and more.

```bash
# One-shot install of the governance pack
npx meok-setup --pack governance
```

Free tier: 10 calls/day per MCP. Pro tier (£79/mo): unlimited + cryptographically signed compliance attestations your auditor verifies independently.

→ Full catalogue: [councilof.ai/catalogue](https://councilof.ai/catalogue)
→ MEOK AI Labs: [meok.ai](https://meok.ai)



## Protocol coverage + Universal PAYG

This MCP is part of MEOK's 47-MCP fleet that bridges every active agent-interop protocol
and 30+ regulatory frameworks. See the full coverage matrix at [meok.ai/protocols](https://meok.ai/protocols).

**Agent interop protocols supported (8 live):**

- ✅ **MCP** (Anthropic) — native
- ✅ **A2A** (Google + Linux Foundation, absorbed IBM ACP Sept 2025)
- ✅ **IBM ACP** — covered via A2A merge
- ◐ **Stripe ACP** (Agentic Commerce Protocol) — Q3 bridge via [agent-commerce-protocol-mcp](https://github.com/CSOAI-ORG/agent-commerce-protocol-mcp)
- ◐ **AP2** (Google Agent Payments) — partial via [agent-commerce-payments-mcp](https://github.com/CSOAI-ORG/agent-commerce-payments-mcp)
- ◐ **x402** (Coinbase HTTP 402) — partial via api.meok.ai gateway
- → **OASF / AGNTCY** (Cisco Outshift + Linux Foundation) — Q3 bridge
- 👁 **ANP** (Cisco Agent Network) — watch-list

**Pricing options:**

| Option | Price | Best for |
|---|---|---|
| Self-host (this MCP) | £0 — MIT | Devs |
| This MCP Starter | £29/mo | One-MCP teams |
| This MCP Pro | £79/mo | Production + 24h SLA |
| [Universal PAYG](https://buy.stripe.com/00w3cxcgAaEGcIBcyQ8k90s) | £29/mo + £0.0002/call | Spiky usage across many MCPs |
| Substrate bundle (this category) | £99-£499/mo | A whole pack |
| [MEOK Universe](https://buy.stripe.com/cNi9AV0xS8wy5g9aqI8k90u) | £1,499/mo | All 47 MCPs, 500K calls |

Each tier above the free self-host adds HMAC-signed attestations verifiable at
`verify.meok.ai`. Linux Foundation governance on the A2A spine means EU regulated
buyers can deploy without vendor-lock-in objections.
