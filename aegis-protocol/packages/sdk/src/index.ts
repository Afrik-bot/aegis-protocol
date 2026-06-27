/**
 * Aegis Protocol SDK — Main Client
 *
 * The primary integration point for the Aegis Protocol.
 *
 * Usage:
 *   import { AegisClient } from '@aegis-protocol/sdk';
 *   const aegis = new AegisClient({ orgId: 'org_...', apiKey: '...' });
 */

import type {
  AegisPassport,
  VerifyRequest,
  VerifyResponse,
  RevokeRequest,
  RevokeResponse,
  AttestationRequest,
  AttestationResponse,
  AuditEvent,
} from '@aegis-protocol/spec';
import { generateKeyPair, generateAttestationId, sha256 } from './utils/crypto';
import type { KeyPair } from './utils/crypto';
import {
  InMemoryPassportStore,
  InMemoryAuditStore,
  type PassportStore,
  type AuditStore,
} from './utils/store';
import { issuePassport, revokePassport, suspendPassport } from './passports/passport';
import type { IssuePassportRequest } from './passports/passport';
import { verify } from './verify/verifier';
import { appendAuditEvent, getAuditLog, verifyAuditChainIntegrity } from './audit/audit';

// ─── Client Config ─────────────────────────────────────────────────────────

export interface AegisClientConfig {
  /** Your organization ID */
  orgId: string;
  /** Your organization's display name */
  orgName?: string;
  /**
   * API key for the Aegis verification service.
   * Not required for the local reference verifier.
   */
  apiKey?: string;
  /**
   * Custom key pair for signing passports.
   * If not provided, a new key pair is generated automatically.
   * 
   * PRODUCTION: Provide a key pair backed by your HSM.
   */
  keyPair?: KeyPair;
  /**
   * Custom storage backends.
   * Default: in-memory stores (data is lost on restart).
   * 
   * PRODUCTION: Provide PostgreSQL-backed implementations.
   */
  stores?: {
    passports?: PassportStore;
    audit?: AuditStore;
  };
}

// ─── AegisClient ──────────────────────────────────────────────────────────

export class AegisClient {
  private readonly orgId: string;
  private readonly orgName: string;
  private readonly keyPair: KeyPair;
  private readonly passportStore: PassportStore;
  private readonly auditStore: AuditStore;

  constructor(config: AegisClientConfig) {
    this.orgId = config.orgId;
    this.orgName = config.orgName ?? config.orgId;
    this.keyPair = config.keyPair ?? generateKeyPair('ES256');
    this.passportStore = config.stores?.passports ?? new InMemoryPassportStore();
    this.auditStore = config.stores?.audit ?? new InMemoryAuditStore();
  }

  // ── Passports ────────────────────────────────────────────────────────────

  readonly passports = {
    /**
     * Issue a new AI Passport for an agent.
     *
     * @example
     * const passport = await aegis.passports.issue({
     *   agentName: 'AnalysisAgent-v2',
     *   agentVersion: '2.4.1',
     *   modelFamily: 'claude-sonnet',
     *   permittedActions: ['read:financial_data', 'write:reports'],
     *   deniedActions: ['write:transactions'],
     * });
     */
    issue: (req: Omit<IssuePassportRequest, 'organizationId' | 'organizationName'>) =>
      issuePassport(
        { ...req, organizationId: this.orgId, organizationName: this.orgName },
        this.keyPair,
        this.passportStore,
        this.auditStore
      ),

    /** Retrieve a passport by ID */
    get: (passportId: string): Promise<AegisPassport | null> =>
      this.passportStore.findById(passportId),

    /** List all passports for your organization */
    list: (): Promise<AegisPassport[]> =>
      this.passportStore.findByOrgId(this.orgId),

    /** Immediately revoke a passport */
    revoke: (req: RevokeRequest): Promise<AegisPassport> =>
      revokePassport(req.passportId, req.reason, req.notes, this.passportStore, this.auditStore),

    /** Suspend a passport pending investigation */
    suspend: (passportId: string, reason: string): Promise<AegisPassport> =>
      suspendPassport(passportId, reason, this.passportStore, this.auditStore),
  };

  // ── Verification ─────────────────────────────────────────────────────────

  /**
   * Verify an agent's passport and receive a trust decision.
   * This is the core operation of the Aegis Protocol.
   *
   * @example
   * const decision = await aegis.verify({
   *   passportId: 'ap_01HZ7K...',
   *   requestedCapabilities: ['read:financial_data'],
   *   riskLevel: 'HIGH',
   * });
   *
   * if (decision.decision === 'ALLOW') {
   *   // proceed with interaction
   * }
   */
  verify(req: VerifyRequest): Promise<VerifyResponse> {
    return verify(req, this.passportStore, this.auditStore);
  }

  // ── Attestation ───────────────────────────────────────────────────────────

  /**
   * Submit a behavioral attestation for an agent.
   * Attestations affect the agent's trust score over time.
   */
  async attest(req: AttestationRequest): Promise<AttestationResponse> {
    const passport = await this.passportStore.findById(req.passportId);
    if (!passport) throw new Error(`Passport not found: ${req.passportId}`);

    const evidenceHash = sha256(req.evidence);
    const attestationId = generateAttestationId();
    const submittedAt = new Date().toISOString();

    // Compute trust score impact based on attestation type
    const impactMap: Record<string, number> = {
      BEHAVIORAL_SAMPLE:  +10,
      POLICY_CHECKPOINT:  +15,
      HUMAN_APPROVAL:     +5,
      CAPABILITY_EXERCISE: +8,
      INCIDENT_REPORT:    -150,
    };
    const trustScoreDelta = impactMap[req.attestationType] ?? 0;

    await appendAuditEvent(this.auditStore, {
      passportId: req.passportId,
      eventType: 'ATTESTATION_SUBMITTED',
      severity: req.severity ?? 'INFO',
      eventData: {
        attestationId,
        attestationType: req.attestationType,
        evidenceHash,
        trustScoreDelta,
      },
    });

    return {
      attestationId,
      passportId: req.passportId,
      attestationType: req.attestationType,
      evidenceHash,
      receiptSignature: `receipt.${Buffer.from(`${attestationId}:${evidenceHash}`).toString('base64url')}`,
      submittedAt,
      trustScoreDelta,
    };
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  readonly audit = {
    /** Retrieve the audit log for a specific passport */
    getLog: (passportId: string, limit?: number): Promise<AuditEvent[]> =>
      getAuditLog(passportId, this.auditStore, limit),

    /** Verify the integrity of the entire audit chain */
    verifyIntegrity: () => verifyAuditChainIntegrity(this.auditStore),
  };

  // ── Key info ──────────────────────────────────────────────────────────────

  /** Return the public key used to verify passport signatures */
  getPublicKey(): string {
    return this.keyPair.publicKey;
  }

  getKeyId(): string {
    return this.keyPair.keyId;
  }
}

// ─── Re-exports ────────────────────────────────────────────────────────────

export { generateKeyPair } from './utils/crypto';
export type { KeyPair } from './utils/crypto';
export type { IssuePassportRequest } from './passports/passport';
export { getTrustTier } from './passports/passport';
export { computeTrustScore } from './verify/trust-score';
export {
  InMemoryPassportStore,
  InMemoryAuditStore,
} from './utils/store';
export type { PassportStore, AuditStore } from './utils/store';
