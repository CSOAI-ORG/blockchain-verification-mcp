# Blockchain Verification MCP Server

> By [MEOK AI Labs](https://meok.ai) — Immutable audit trails with SHA-256 hash chain verification for compliance certifications

## Installation

```bash
pip install blockchain-verification-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install blockchain-verification-mcp
```

## Tools

### `mint_certificate`
Mint a blockchain-backed certificate with SHA-256 hash chain verification.

**Parameters:**
- `organization` (str): Organization name
- `framework` (str): Compliance framework
- `scope` (str): Certificate scope

### `verify_certificate`
Verify a certificate's authenticity by checking its hash chain and signatures.

**Parameters:**
- `certificate_id` (str): Certificate identifier

### `audit_trail`
Get the full audit trail for an organization including all verification events.

**Parameters:**
- `organization` (str): Organization name

### `integrity_check`
Run integrity checks on the certificate store to detect tampering or corruption.

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
