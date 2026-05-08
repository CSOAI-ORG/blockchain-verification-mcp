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
