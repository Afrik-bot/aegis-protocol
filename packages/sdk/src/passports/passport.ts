/**
 * Aegis Protocol SDK — Passport Issuance
 *
 * Issues cryptographically signed AI Passports for autonomous agents.
 */

import type {
  AegisPassport,
  AgentSubject,
  CapabilityScope,
  DeploymentEnv,
  Jurisdiction,
  ModelFamily,
} from '@aegis-protocol/spec';
import {
  AEGIS_VERSION,
  PASSPORT_DEFAULT_VALIDITY_DAYS,
  TRUST_TIER_THRESHOLDS,
} from '@aegis-protocol/spec';
import type { KeyPair } from '../utils/crypto';
import {
  generatePassportId,
  generateAgentId,
  sign,
  mockCertificate,
  sha256,
  canonicalize,
} from '../utils/crypto';
import type { PassportStore, AuditStore } from '../utils/store';
import { appendAuditEvent } from '../audit/audit';

// ─── Issue Request ─────────────────────────────────────────────────────────

export interface IssuePassportRequest {
  agentName: string;
  agentVersion?: string;
  modelFamily?: ModelFamily;
  deploymentEnv?: DeploymentEnv;
  jurisdiction?: Jurisdiction;
  organizationId: string;
  organizationName: string;
  permittedActions: string[];
  deniedActions?: string[];
  requiresHumanApproval?: string[];
  maxTransactionValueUsd?: number;
  validityDays?: number;
}

// ─── Derive trust tier from score ─────────────────────────────────────────

export function getTrustTier(score: number): AegisPassport['trustMetadata']['trustTier'] {
  if (score >= TRUST_TIER_THRESHOLDS.TRUSTED)  return 'TRUSTED';
  if (score >= TRUST_TIER_THRESHOLDS.ELEVATED) return 'ELEVATED';
  if (score >= TRUST_TIER_THRESHOLDS.STANDARD) return 'STANDARD';
  if (score >= TRUST_TIER_THRESHOLDS.LOW)      return 'LOW';
  return 'CRITICAL';
}

// ─── Build passport payload (unsigned) ────────────────────────────────────

function buildPassportPayload(
  req: IssuePassportRequest,
  passportId: string,
  agentId: string,
  keyPair: KeyPair,
  issuedAt: Date,
  expiresAt: Date
): Omit<AegisPassport, 'signature'> {
  const subject: AgentSubject = {
    agentId,
    agentName: req.agentName,
    agentVersion: req.agentVersion ?? '1.0.0',
    modelFamily: req.modelFamily ?? 'custom',
    organizationId: req.organizationId,
    organizationName: req.organizationName,
    deploymentEnv: req.deploymentEnv ?? 'production',
    jurisdiction: req.jurisdiction ?? 'US',
  };

  const capabilities: CapabilityScope = {
    permittedActions: req.permittedActions,
    deniedActions: req.deniedActions ?? [],
    requiresHumanApproval: req.requiresHumanApproval ?? [],
    maxTransactionValueUsd: req.maxTransactionValueUsd ?? 0,
  };

  // Initial trust score: production agents start at 850 (TRUSTED),
  // non-production agents start lower to reflect lower assurance.
  const initialTrustScore = req.deploymentEnv === 'production' ? 850 : 650;

  return {
    aegisVersion: AEGIS_VERSION,
    passportId,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    status: 'ACTIVE',
    issuer: {
      authorityId: `aia_reference_${req.organizationId}`,
      authorityName: `${req.organizationName} Reference Authority`,
      certificateChain: [mockCertificate(keyPair.keyId)],
    },
    subject,
    capabilities,
    trustMetadata: {
      initialTrustScore,
      trustTier: getTrustTier(initialTrustScore),
      behavioralBaselineHash: sha256({ agentName: req.agentName, capabilities }),
      policyFramework: 'NIST_AI_RMF_1.0',
    },
  };
}

// ─── Issue ─────────────────────────────────────────────────────────────────

export async function issuePassport(
  req: IssuePassportRequest,
  keyPair: KeyPair,
  passportStore: PassportStore,
  auditStore: AuditStore
): Promise<AegisPassport> {
  const passportId = generatePassportId();
  const agentId = generateAgentId();
  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + (req.validityDays ?? PASSPORT_DEFAULT_VALIDITY_DAYS));

  // Build the payload to sign
  const payload = buildPassportPayload(req, passportId, agentId, keyPair, now, expiresAt);

  // Sign the canonical JSON of the payload
  const signatureValue = sign(payload, keyPair.privateKey, keyPair.algorithm);

  const passport: AegisPassport = {
    ...payload,
    signature: {
      algorithm: keyPair.algorithm,
      keyId: keyPair.keyId,
      value: signatureValue,
    },
  };

  // Persist
  await passportStore.save(passport);

  // Audit
  await appendAuditEvent(auditStore, {
    passportId,
    eventType: 'PASSPORT_ISSUED',
    severity: 'INFO',
    eventData: {
      agentName: req.agentName,
      organizationId: req.organizationId,
      permittedActionsCount: req.permittedActions.length,
      expiresAt: expiresAt.toISOString(),
    },
  });

  return passport;
}

// ─── Revoke ────────────────────────────────────────────────────────────────

export async function revokePassport(
  passportId: string,
  reason: AegisPassport['revocationReason'],
  notes: string | undefined,
  passportStore: PassportStore,
  auditStore: AuditStore
): Promise<AegisPassport> {
  const passport = await passportStore.findById(passportId);
  if (!passport) throw new Error(`Passport not found: ${passportId}`);
  if (passport.status === 'REVOKED') throw new Error(`Passport already revoked: ${passportId}`);

  const revokedAt = new Date().toISOString();
  const updated = await passportStore.update(passportId, {
    status: 'REVOKED',
    revokedAt,
    revocationReason: reason,
  });

  await appendAuditEvent(auditStore, {
    passportId,
    eventType: 'PASSPORT_REVOKED',
    severity: 'HIGH',
    eventData: { reason, notes, revokedAt },
  });

  return updated!;
}

// ─── Suspend / Reinstate ──────────────────────────────────────────────────

export async function suspendPassport(
  passportId: string,
  reason: string,
  passportStore: PassportStore,
  auditStore: AuditStore
): Promise<AegisPassport> {
  const passport = await passportStore.findById(passportId);
  if (!passport) throw new Error(`Passport not found: ${passportId}`);

  const updated = await passportStore.update(passportId, { status: 'SUSPENDED' });

  await appendAuditEvent(auditStore, {
    passportId,
    eventType: 'PASSPORT_SUSPENDED',
    severity: 'MEDIUM',
    eventData: { reason },
  });

  return updated!;
}

// ─── Validate (check expiry, status) ─────────────────────────────────────

export function validatePassportStatus(passport: AegisPassport): { valid: boolean; reason?: string } {
  if (passport.status === 'REVOKED') return { valid: false, reason: 'Passport has been revoked' };
  if (passport.status === 'SUSPENDED') return { valid: false, reason: 'Passport is suspended pending investigation' };
  if (passport.status === 'EXPIRED') return { valid: false, reason: 'Passport has expired' };
  if (new Date(passport.expiresAt) < new Date()) return { valid: false, reason: 'Passport has expired' };
  if (passport.status !== 'ACTIVE') return { valid: false, reason: `Passport status is ${passport.status}` };
  return { valid: true };
}

// ─── Verify passport signature ────────────────────────────────────────────

export function verifyPassportIntegrity(
  passport: AegisPassport,
  publicKeyPem: string
): boolean {
  const { signature, ...payload } = passport;
  // Re-canonicalize payload and verify signature
  const { verifySignature } = require('../utils/crypto');
  return verifySignature(payload, signature.value, publicKeyPem, signature.algorithm);
}
