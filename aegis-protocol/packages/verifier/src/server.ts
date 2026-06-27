/**
 * Aegis Protocol — Reference Verifier
 *
 * A minimal HTTP server implementing the Aegis Protocol verification API.
 * Uses only Node.js built-ins — no Express or external HTTP frameworks required.
 *
 * This is a reference implementation. For production:
 * - Add TLS (never run HTTP in production)
 * - Add authentication (verify relying party API keys)
 * - Replace in-memory stores with a real database
 * - Deploy behind a load balancer with health checks
 *
 * Usage:
 *   npm run dev         # TypeScript, auto-reload
 *   npm start           # Compiled JavaScript
 *
 * Endpoints:
 *   POST /v1/passports           Issue a new AI Passport
 *   GET  /v1/passports/:id       Retrieve a passport
 *   POST /v1/passports/:id/revoke  Revoke a passport
 *   POST /v1/verify              Verify a passport + get trust decision
 *   POST /v1/attestations        Submit a behavioral attestation
 *   GET  /v1/audit/:passportId   Retrieve audit log
 *   GET  /v1/health              Health check
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { AegisClient } from '@aegis-protocol/sdk';
import type { IssuePassportRequest } from '@aegis-protocol/sdk';
import type {
  VerifyRequest,
  RevokeRequest,
  AttestationRequest,
} from '@aegis-protocol/spec';

// ─── Configuration ─────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const ORG_ID = process.env.AEGIS_ORG_ID ?? 'org_reference_verifier';
const ORG_NAME = process.env.AEGIS_ORG_NAME ?? 'Aegis Reference Verifier';

// ─── Client ────────────────────────────────────────────────────────────────

const aegis = new AegisClient({ orgId: ORG_ID, orgName: ORG_NAME });

// ─── HTTP helpers ──────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw.length > 0 ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-Aegis-Version': '1.0',
  });
  res.end(json);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  send(res, status, { error: { code: status, message } });
}

// ─── Route handler ─────────────────────────────────────────────────────────

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url ?? '/';
  const method = req.method ?? 'GET';

  // ── GET /v1/health ────────────────────────────────────────────────────────
  if (method === 'GET' && url === '/v1/health') {
    return send(res, 200, {
      status: 'ok',
      aegisVersion: '1.0',
      orgId: ORG_ID,
      timestamp: new Date().toISOString(),
    });
  }

  // ── POST /v1/passports ────────────────────────────────────────────────────
  if (method === 'POST' && url === '/v1/passports') {
    const body = await readBody(req) as Partial<IssuePassportRequest>;
    if (!body.agentName) return sendError(res, 400, 'agentName is required');
    if (!body.permittedActions?.length) return sendError(res, 400, 'permittedActions must not be empty');

    const passport = await aegis.passports.issue(body as IssuePassportRequest);
    return send(res, 201, passport);
  }

  // ── GET /v1/passports/:id ─────────────────────────────────────────────────
  const passportMatch = url.match(/^\/v1\/passports\/([^/]+)$/);
  if (method === 'GET' && passportMatch) {
    const passport = await aegis.passports.get(passportMatch[1]);
    if (!passport) return sendError(res, 404, 'Passport not found');
    return send(res, 200, passport);
  }

  // ── POST /v1/passports/:id/revoke ─────────────────────────────────────────
  const revokeMatch = url.match(/^\/v1\/passports\/([^/]+)\/revoke$/);
  if (method === 'POST' && revokeMatch) {
    const body = await readBody(req) as Partial<RevokeRequest>;
    if (!body.reason) return sendError(res, 400, 'reason is required');

    const passport = await aegis.passports.revoke({
      passportId: revokeMatch[1],
      reason: body.reason,
      notes: body.notes,
    });
    return send(res, 200, passport);
  }

  // ── POST /v1/verify ───────────────────────────────────────────────────────
  if (method === 'POST' && url === '/v1/verify') {
    const body = await readBody(req) as Partial<VerifyRequest>;
    if (!body.passportId) return sendError(res, 400, 'passportId is required');
    if (!body.requestedCapabilities?.length) {
      return sendError(res, 400, 'requestedCapabilities must not be empty');
    }

    const result = await aegis.verify(body as VerifyRequest);
    return send(res, 200, result);
  }

  // ── POST /v1/attestations ─────────────────────────────────────────────────
  if (method === 'POST' && url === '/v1/attestations') {
    const body = await readBody(req) as Partial<AttestationRequest>;
    if (!body.passportId) return sendError(res, 400, 'passportId is required');
    if (!body.attestationType) return sendError(res, 400, 'attestationType is required');

    const result = await aegis.attest(body as AttestationRequest);
    return send(res, 201, result);
  }

  // ── GET /v1/audit/:passportId ─────────────────────────────────────────────
  const auditMatch = url.match(/^\/v1\/audit\/([^/]+)(\?.*)?$/);
  if (method === 'GET' && auditMatch) {
    const params = new URLSearchParams(auditMatch[2]?.slice(1) ?? '');
    const limit = parseInt(params.get('limit') ?? '50', 10);
    const events = await aegis.audit.getLog(auditMatch[1], limit);
    return send(res, 200, { events, count: events.length });
  }

  // ── GET /v1/audit/integrity ───────────────────────────────────────────────
  if (method === 'GET' && url === '/v1/audit/integrity') {
    const result = await aegis.audit.verifyIntegrity();
    return send(res, result.valid ? 200 : 500, result);
  }

  sendError(res, 404, `No route: ${method} ${url}`);
}

// ─── Server ────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    sendError(res, 500, message);
  }
});

server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║     AEGIS PROTOCOL — Reference Verifier    ║
║     Trust. Verified. Every AI Agent.       ║
╠════════════════════════════════════════════╣
║  Listening on  http://localhost:${PORT}       ║
║  Org ID:       ${ORG_ID.padEnd(28)}║
║  Version:      Aegis Protocol v1.0         ║
╠════════════════════════════════════════════╣
║  POST /v1/passports      Issue passport    ║
║  POST /v1/verify         Verify agent      ║
║  POST /v1/attestations   Submit evidence   ║
║  GET  /v1/health         Health check      ║
╚════════════════════════════════════════════╝
  `.trim());
});

export default server;
