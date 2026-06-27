# Aegis Protocol

**Open source · MIT licensed · [verisaegis.com](https://verisaegis.com)**

> Every line of the Aegis Protocol — spec, SDKs, and reference verifier — is open source. Fork it, audit it, run it yourself.

Aegis Protocol is the identity and trust layer for autonomous AI agents. It gives every agent a cryptographically verifiable **AI Passport**, a real-time **Trust Score**, and a tamper-evident **Audit Trail** — the same accountability infrastructure you would apply to a human employee, built for the speed and scale that AI actually operates at.

---

## The Problem

Autonomous AI agents are reading files, sending emails, moving money, and making decisions — at scale, in production. Yet there is no standard way to answer the most basic questions about them:

- Who authorized this agent?
- What is it actually allowed to do?
- What did it do, and when?
- Who is accountable if something goes wrong?

Aegis Protocol answers all four.

---

## What's in this repository

```
aegis-protocol/
├── packages/
│   ├── spec/          # Protocol specification types, schemas, and constants
│   ├── sdk/           # TypeScript SDK — issue, verify, revoke, attest
│   └── verifier/      # Reference verifier — standalone trust decision engine
├── examples/          # Working examples for common use cases
├── docs/              # Protocol documentation
└── .github/workflows/ # CI/CD
```

### `@aegis-protocol/spec`
Canonical TypeScript types, JSON schemas, and constants for the Aegis Protocol v1.0. This is the source of truth for the data model. All other packages depend on it.

### `@aegis-protocol/sdk`
The primary integration point. Use this to:
- Issue AI Passports for your agents
- Verify any agent's passport and receive a trust decision
- Revoke passports immediately
- Submit behavioral attestations
- Read audit logs

### `@aegis-protocol/verifier`
A standalone reference implementation of the Aegis trust decision engine. Implements the full Trust Score algorithm, capability scope checking, and behavioral baseline comparison. Can be run as a library or as a lightweight HTTP service.

---

## Quick Start

```bash
npm install @aegis-protocol/sdk
```

```typescript
import { AegisClient } from '@aegis-protocol/sdk';

const aegis = new AegisClient({
  orgId: 'org_your_org_id',
  apiKey: process.env.AEGIS_API_KEY,
});

// Issue a passport for your agent
const passport = await aegis.passports.issue({
  agentName: 'AnalysisAgent-v2',
  agentVersion: '2.4.1',
  modelFamily: 'claude-sonnet',
  deploymentEnv: 'production',
  permittedActions: ['read:financial_data', 'write:reports'],
  deniedActions: ['write:transactions', 'delete:records'],
  requiresHumanApproval: ['call:external_api'],
  jurisdiction: 'US',
});

console.log('Passport issued:', passport.passportId);
// ap_01HZ7K3N8P2Q4R5S6T7U8V9W0X

// Verify any agent before a sensitive interaction
const decision = await aegis.verify({
  passportId: passport.passportId,
  requestedCapabilities: ['read:financial_data'],
  interactionType: 'data_access',
  riskLevel: 'HIGH',
});

console.log(decision.decision);   // 'ALLOW' | 'DENY' | 'REVIEW'
console.log(decision.trustScore); // 892
console.log(decision.latencyMs);  // 23
```

---

## Protocol Overview

### AI Passport
A cryptographically signed credential that binds an agent's identity, organizational affiliation, capability scope, and behavioral baseline to a verifiable token.

```typescript
// Passport structure (simplified)
{
  aegisVersion: '1.0',
  passportId: 'ap_01HZ7K3N8P2Q4R5S6T7U8V9W0X',
  issuedAt: '2026-06-01T00:00:00Z',
  expiresAt: '2027-06-01T00:00:00Z',
  subject: {
    agentId: 'agt_8f3a2b1c9d0e4f5a6b7c8d9e0f1a2b3c',
    agentName: 'AnalysisAgent-v2',
    organizationId: 'org_acme_financial_001',
  },
  capabilities: {
    permittedActions: ['read:financial_data', 'write:reports'],
    deniedActions: ['write:transactions'],
    requiresHumanApproval: ['call:external_api'],
  },
  trustMetadata: {
    initialTrustScore: 850,
    trustTier: 'TRUSTED',
  },
  signature: { algorithm: 'ES256', value: '...' }
}
```

### Trust Score
A continuous 0–1000 composite score across five signal families:

| Signal | Weight | Measures |
|--------|--------|---------|
| Identity confidence | 30% | Certificate validity, key storage, rotation recency |
| Behavioral baseline | 25% | Drift from declared behavioral profile |
| Compliance posture | 20% | Policy checkpoint adherence |
| Historical record | 15% | Time-decayed incident/attestation history |
| Environmental risk | 10% | Deployment context, jurisdiction, risk flags |

### Trust Tiers

| Tier | Score | Default behavior |
|------|-------|-----------------|
| TRUSTED | 850–1000 | Full passport scope; async monitoring |
| ELEVATED | 650–849 | Expanded scope; reduced friction |
| STANDARD | 400–649 | Standard operational scope |
| LOW | 200–399 | Read-only; no external calls |
| CRITICAL | 0–199 | Blocked; mandatory human review |

### Trust Handshake Protocol
Three-phase mutual verification before any sensitive agent-to-agent interaction:
1. **HELLO** — agent presents passport + nonce
2. **CHALLENGE** — verifier checks passport, returns policy challenge
3. **RESPONSE** — agent signs challenge, receives scoped capability token

---

## Running the Reference Verifier

The reference verifier can run standalone as a local trust decision service:

```bash
cd packages/verifier
npm install
npm run dev
# Listening on http://localhost:3000
```

```bash
# Issue a passport
curl -X POST http://localhost:3000/v1/passports \
  -H 'Content-Type: application/json' \
  -d '{"agentName":"TestAgent","permittedActions":["read:data"]}'

# Verify it
curl -X POST http://localhost:3000/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"passportId":"ap_...","requestedCapabilities":["read:data"]}'
```

---

## Compliance

Aegis Protocol provides structural evidence for:

- **NIST AI RMF 1.0** — GOVERN, MAP, MEASURE, MANAGE functions
- **EU AI Act** — Articles 11 (documentation), 12 (logging), 13 (transparency), 14 (human oversight)
- **SOC 2 Type II** — CC6, CC7, A1, PI1 criteria
- **ISO/IEC 42001** — Clauses 9 and 10

---

## Security

This is a **reference implementation**. It is designed to demonstrate the protocol and provide a foundation for production systems. Before deploying in a production environment handling sensitive data:

- Replace the software-based signing with HSM-backed keys
- Conduct a formal security audit
- Run penetration testing against your deployment
- Review the threat model in `docs/THREAT_MODEL.md`

Found a vulnerability? Please report it privately to **security@verisaegis.com** rather than opening a public issue.

---

## Contributing

We welcome contributions. Please read `CONTRIBUTING.md` before opening a pull request.

- **Spec changes** require an RFC discussion issue before implementation
- **SDK changes** require tests covering the new behavior
- **Verifier changes** require the full test suite to pass

---

## License

MIT © 2026 Veris Inc.

---

*Built by [Veris Inc.](https://verisaegis.com) — Trust. Verified. Every AI Agent.*
