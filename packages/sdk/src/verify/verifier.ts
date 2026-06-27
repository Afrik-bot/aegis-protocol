/**
 * Aegis Protocol SDK — Verification Engine
 *
 * Implements the VERIFY primitive of the Aegis Protocol.
 * Returns a trust decision (ALLOW / DENY / REVIEW) with full audit trail.
 */

import type {
  VerifyRequest,
  VerifyResponse,
  TrustDecision,
  AegisPassport,
} from '@aegis-protocol/spec';
import {
  TRUST_TIER_THRESHOLDS,
  CAPABILITY_TOKEN_DEFAULT_TTL_SECONDS,
} from '@aegis-protocol/spec';
import { computeTrustScore } from './trust-score';
import { validatePassportStatus } from '../passports/passport';
import { appendAuditEvent } from '../audit/audit';
import { randomId } from '../utils/crypto';
import type { PassportStore, AuditStore } from '../utils/store';

// ─── Capability Scope Check ────────────────────────────────────────────────

function checkCapabilityScope(
  passport: AegisPassport,
  requestedCapabilities: string[]
): { allowed: boolean; denied: string[]; requiresApproval: string[] } {
  const denied: string[] = [];
  const requiresApproval: string[] = [];

  for (const cap of requestedCapabilities) {
    // Explicit deny takes precedence
    if (passport.capabilities.deniedActions.includes(cap)) {
      denied.push(cap);
      continue;
    }

    // Check if permitted (supports wildcard "verb:*" matching)
    const isPermitted = passport.capabilities.permittedActions.some(permitted => {
      if (permitted === cap) return true;
      if (permitted.endsWith(':*')) {
        const prefix = permitted.slice(0, -1); // "read:" 
        return cap.startsWith(prefix);
      }
      return false;
    });

    if (!isPermitted) {
      denied.push(cap);
      continue;
    }

    // Check if human approval required
    if (passport.capabilities.requiresHumanApproval.includes(cap)) {
      requiresApproval.push(cap);
    }
  }

  return {
    allowed: denied.length === 0,
    denied,
    requiresApproval,
  };
}

// ─── Generate capability token ─────────────────────────────────────────────

function generateCapabilityToken(
  passport: AegisPassport,
  requestedCapabilities: string[],
  ttlSeconds: number
): string {
  const payload = {
    sub: passport.passportId,
    agt: passport.subject.agentId,
    org: passport.subject.organizationId,
    cap: requestedCapabilities,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    jti: randomId(16),
  };

  // In production this would be a proper signed JWT.
  // Reference implementation uses base64url encoding.
  return `captoken.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
}

// ─── Core verify function ──────────────────────────────────────────────────

export async function verify(
  req: VerifyRequest,
  passportStore: PassportStore,
  auditStore: AuditStore
): Promise<VerifyResponse> {
  const startMs = Date.now();
  const warnings: string[] = [];

  // 1. Fetch passport
  const passport = await passportStore.findById(req.passportId);
  if (!passport) {
    const latencyMs = Date.now() - startMs;
    await appendAuditEvent(auditStore, {
      passportId: req.passportId,
      eventType: 'VERIFICATION_DENY',
      severity: 'HIGH',
      eventData: { reason: 'PASSPORT_NOT_FOUND', requestedCapabilities: req.requestedCapabilities },
    });
    return buildDenyResponse('Passport not found', req, latencyMs);
  }

  // 2. Check passport status and expiry
  const statusCheck = validatePassportStatus(passport);
  if (!statusCheck.valid) {
    const latencyMs = Date.now() - startMs;
    await appendAuditEvent(auditStore, {
      passportId: req.passportId,
      eventType: 'VERIFICATION_DENY',
      severity: 'HIGH',
      eventData: { reason: statusCheck.reason, status: passport.status },
    });
    return buildDenyResponse(statusCheck.reason!, req, latencyMs);
  }

  // 3. Warn if passport expires within 30 days
  const daysToExpiry = (new Date(passport.expiresAt).getTime() - Date.now()) / 86400000;
  if (daysToExpiry < 30) {
    warnings.push(`Passport expires in ${Math.floor(daysToExpiry)} days. Consider renewal.`);
  }

  // 4. Check capability scope
  const scopeCheck = checkCapabilityScope(passport, req.requestedCapabilities);
  if (!scopeCheck.allowed) {
    const latencyMs = Date.now() - startMs;
    await appendAuditEvent(auditStore, {
      passportId: req.passportId,
      eventType: 'VERIFICATION_DENY',
      severity: 'HIGH',
      eventData: {
        reason: 'CAPABILITY_NOT_PERMITTED',
        deniedCapabilities: scopeCheck.denied,
        requestedCapabilities: req.requestedCapabilities,
      },
    });
    return buildDenyResponse(
      `Requested capabilities not permitted: ${scopeCheck.denied.join(', ')}`,
      req,
      Date.now() - startMs
    );
  }

  // 5. Compute trust score
  const riskLevel = req.riskLevel ?? 'MEDIUM';
  const { score, tier, components } = computeTrustScore({ passport, riskLevel });

  // 6. Decision logic
  let decision: TrustDecision;
  let auditEventType: 'VERIFICATION_ALLOW' | 'VERIFICATION_DENY' | 'VERIFICATION_REVIEW';

  if (score < TRUST_TIER_THRESHOLDS.LOW) {
    // CRITICAL tier — always deny
    decision = 'DENY';
    auditEventType = 'VERIFICATION_DENY';
  } else if (
    score < TRUST_TIER_THRESHOLDS.STANDARD ||
    scopeCheck.requiresApproval.length > 0 ||
    (riskLevel === 'HIGH' && score < TRUST_TIER_THRESHOLDS.TRUSTED) ||
    (riskLevel === 'CRITICAL')
  ) {
    // LOW tier, or requires human approval, or high-risk with non-TRUSTED score
    decision = 'REVIEW';
    auditEventType = 'VERIFICATION_REVIEW';
    if (scopeCheck.requiresApproval.length > 0) {
      warnings.push(`Human approval required for: ${scopeCheck.requiresApproval.join(', ')}`);
    }
  } else {
    decision = 'ALLOW';
    auditEventType = 'VERIFICATION_ALLOW';
  }

  const latencyMs = Date.now() - startMs;
  const validUntil = new Date(Date.now() + CAPABILITY_TOKEN_DEFAULT_TTL_SECONDS * 1000).toISOString();

  // 7. Generate capability token for ALLOW decisions
  const capabilityToken = decision === 'ALLOW'
    ? generateCapabilityToken(passport, req.requestedCapabilities, CAPABILITY_TOKEN_DEFAULT_TTL_SECONDS)
    : undefined;

  // 8. Audit
  const { generateAuditReceiptId } = require('../utils/crypto');
  const auditReceiptId = generateAuditReceiptId();

  await appendAuditEvent(auditStore, {
    passportId: req.passportId,
    eventType: auditEventType,
    severity: decision === 'DENY' ? 'HIGH' : decision === 'REVIEW' ? 'MEDIUM' : 'INFO',
    eventData: {
      decision,
      trustScore: score,
      trustTier: tier,
      requestedCapabilities: req.requestedCapabilities,
      relyingParty: req.relyingParty,
      riskLevel,
      latencyMs,
      auditReceiptId,
    },
  });

  return {
    decision,
    trustScore: score,
    trustTier: tier,
    validUntil,
    capabilityToken,
    auditReceiptId,
    warnings,
    scoreComponents: components,
    latencyMs,
  };
}

// ─── Helper ────────────────────────────────────────────────────────────────

function buildDenyResponse(
  reason: string,
  req: VerifyRequest,
  latencyMs: number
): VerifyResponse {
  return {
    decision: 'DENY',
    trustScore: 0,
    trustTier: 'CRITICAL',
    validUntil: new Date().toISOString(),
    auditReceiptId: `ar_${Date.now()}`,
    warnings: [reason],
    scoreComponents: {
      identity: 0, behavioral: 0, compliance: 0, historical: 0, environmental: 0,
    },
    latencyMs,
  };
}
