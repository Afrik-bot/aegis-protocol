/**
 * Aegis Protocol v1.0 — Core Types
 * 
 * Canonical TypeScript definitions for the Aegis Protocol data model.
 * All SDK and verifier implementations MUST conform to these types.
 * 
 * @license MIT
 * @copyright 2026 Veris Inc.
 */

// ─── Identity ──────────────────────────────────────────────────────────────

export type DeploymentEnv = 'development' | 'staging' | 'production';
export type Jurisdiction = 'US' | 'EU' | 'UK' | 'APAC' | 'GLOBAL';
export type ModelFamily =
  | 'claude-sonnet'
  | 'claude-opus'
  | 'claude-haiku'
  | 'gpt-4o'
  | 'gpt-4'
  | 'gemini-pro'
  | 'gemini-ultra'
  | 'llama-3'
  | 'mistral'
  | 'custom';

export interface AgentSubject {
  /** Unique agent identifier. Format: agt_{32 hex chars} */
  agentId: string;
  /** Human-readable agent name */
  agentName: string;
  /** Semantic version of the agent */
  agentVersion: string;
  /** The model family powering this agent */
  modelFamily: ModelFamily;
  /** Issuing organization identifier */
  organizationId: string;
  /** Human-readable organization name */
  organizationName: string;
  /** Deployment environment */
  deploymentEnv: DeploymentEnv;
  /** Primary legal jurisdiction for compliance mapping */
  jurisdiction: Jurisdiction;
}

// ─── Capabilities ─────────────────────────────────────────────────────────

/**
 * Action strings follow the pattern "verb:resource"
 * e.g. "read:financial_data", "write:reports", "call:external_api"
 */
export type ActionScope = string;

export interface CapabilityScope {
  /** Actions this agent is explicitly authorized to perform */
  permittedActions: ActionScope[];
  /** Actions this agent is explicitly forbidden from performing */
  deniedActions: ActionScope[];
  /**
   * Actions that require explicit human approval before execution.
   * Must be a subset of permittedActions.
   */
  requiresHumanApproval: ActionScope[];
  /** Maximum transaction value in USD (0 = no financial transactions) */
  maxTransactionValueUsd?: number;
}

// ─── Trust ────────────────────────────────────────────────────────────────

export type TrustTier = 'TRUSTED' | 'ELEVATED' | 'STANDARD' | 'LOW' | 'CRITICAL';

export interface TrustMetadata {
  /** Initial trust score assigned at issuance [0–1000] */
  initialTrustScore: number;
  /** Trust tier derived from initialTrustScore */
  trustTier: TrustTier;
  /**
   * SHA-256 hash of the behavioral baseline snapshot taken at issuance.
   * Used to detect drift in future trust evaluations.
   */
  behavioralBaselineHash?: string;
  /** Policy framework this passport is governed by */
  policyFramework?: string;
}

// ─── Cryptographic Signature ──────────────────────────────────────────────

export type SignatureAlgorithm = 'ES256' | 'ES384';

export interface PassportSignature {
  /** Signing algorithm */
  algorithm: SignatureAlgorithm;
  /** Key identifier for the signing key */
  keyId: string;
  /** Base64url-encoded signature value */
  value: string;
}

// ─── Issuer ───────────────────────────────────────────────────────────────

export interface PassportIssuer {
  /** Unique identifier for the issuing authority */
  authorityId: string;
  /** Human-readable name of the issuing authority */
  authorityName: string;
  /**
   * PEM-encoded certificate chain from issuing CA to root.
   * [0] = issuing CA cert, [N] = closest to root
   */
  certificateChain: string[];
}

// ─── Passport ─────────────────────────────────────────────────────────────

export type PassportStatus =
  | 'DRAFT'
  | 'PENDING'
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'EXPIRED';

/**
 * AI Passport — the core credential of the Aegis Protocol.
 * 
 * A signed, verifiable credential that binds an AI agent's identity,
 * organizational affiliation, capability scope, and behavioral baseline
 * to a tamper-evident token.
 */
export interface AegisPassport {
  /** Protocol version. Must be "1.0" for this spec. */
  aegisVersion: '1.0';
  /** Globally unique passport identifier. Format: ap_{26 alphanumeric chars} */
  passportId: string;
  /** ISO 8601 timestamp of issuance */
  issuedAt: string;
  /** ISO 8601 timestamp of expiry. Default: 1 year from issuedAt */
  expiresAt: string;
  /** Current lifecycle status */
  status: PassportStatus;
  /** The issuing authority */
  issuer: PassportIssuer;
  /** The agent this passport describes */
  subject: AgentSubject;
  /** What the agent is and is not allowed to do */
  capabilities: CapabilityScope;
  /** Trust scoring metadata */
  trustMetadata: TrustMetadata;
  /** Cryptographic signature over the passport contents */
  signature: PassportSignature;
  /** ISO 8601 timestamp of revocation (if status === 'REVOKED') */
  revokedAt?: string;
  /** Reason for revocation */
  revocationReason?: RevocationReason;
}

// ─── Verification ─────────────────────────────────────────────────────────

export type TrustDecision = 'ALLOW' | 'DENY' | 'REVIEW';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface VerifyRequest {
  /** The passport to verify */
  passportId: string;
  /**
   * The full signed passport JWT (optional if the verifier can look it up).
   * Providing it avoids a registry lookup and reduces latency.
   */
  passportJwt?: string;
  /** Capabilities the calling system needs for this interaction */
  requestedCapabilities: ActionScope[];
  /** Type of interaction being requested */
  interactionType?: string;
  /** Risk level of the interaction as assessed by the relying party */
  riskLevel?: RiskLevel;
  /** Identifier of the relying party making the request */
  relyingParty?: string;
  /** Additional context for the trust decision */
  context?: Record<string, unknown>;
}

export interface TrustScoreComponents {
  /** Identity confidence score [0–1000] */
  identity: number;
  /** Behavioral baseline adherence score [0–1000] */
  behavioral: number;
  /** Compliance posture score [0–1000] */
  compliance: number;
  /** Historical incident-free record score [0–1000] */
  historical: number;
  /** Environmental risk adjustment score [0–1000] */
  environmental: number;
}

export interface VerifyResponse {
  /** Trust decision */
  decision: TrustDecision;
  /** Composite trust score at time of verification [0–1000] */
  trustScore: number;
  /** Trust tier derived from trustScore */
  trustTier: TrustTier;
  /** ISO 8601 timestamp until which this decision is valid */
  validUntil: string;
  /**
   * Short-lived capability token scoped to the requested capabilities.
   * Present only when decision === 'ALLOW'.
   */
  capabilityToken?: string;
  /** Audit receipt identifier for this verification event */
  auditReceiptId: string;
  /** Non-blocking warnings (does not affect decision) */
  warnings: string[];
  /** Score component breakdown */
  scoreComponents: TrustScoreComponents;
  /** Milliseconds taken to compute this decision */
  latencyMs: number;
}

// ─── Revocation ───────────────────────────────────────────────────────────

export type RevocationReason =
  | 'SECURITY_INCIDENT'
  | 'POLICY_VIOLATION'
  | 'SCOPE_CHANGE'
  | 'DECOMMISSIONED'
  | 'ORGANIZATION_OFFBOARDING'
  | 'OTHER';

export interface RevokeRequest {
  passportId: string;
  reason: RevocationReason;
  notes?: string;
}

export interface RevokeResponse {
  passportId: string;
  revokedAt: string;
  reason: RevocationReason;
  auditReceiptId: string;
}

// ─── Attestation ──────────────────────────────────────────────────────────

export type AttestationType =
  | 'BEHAVIORAL_SAMPLE'
  | 'POLICY_CHECKPOINT'
  | 'HUMAN_APPROVAL'
  | 'CAPABILITY_EXERCISE'
  | 'INCIDENT_REPORT';

export type AttestationSeverity = 'INFO' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AttestationRequest {
  passportId: string;
  attestationType: AttestationType;
  /** Structured evidence payload */
  evidence: Record<string, unknown>;
  /** Severity of this attestation event */
  severity?: AttestationSeverity;
}

export interface AttestationResponse {
  attestationId: string;
  passportId: string;
  attestationType: AttestationType;
  /** SHA-256 hash of the evidence payload */
  evidenceHash: string;
  /** Signed receipt for this attestation */
  receiptSignature: string;
  submittedAt: string;
  /** Trust score impact (positive or negative) */
  trustScoreDelta: number;
}

// ─── Audit ────────────────────────────────────────────────────────────────

export type AuditEventType =
  | 'PASSPORT_ISSUED'
  | 'PASSPORT_REVOKED'
  | 'PASSPORT_SUSPENDED'
  | 'PASSPORT_EXPIRED'
  | 'VERIFICATION_ALLOW'
  | 'VERIFICATION_DENY'
  | 'VERIFICATION_REVIEW'
  | 'ATTESTATION_SUBMITTED'
  | 'TRUST_SCORE_UPDATED'
  | 'HUMAN_APPROVAL_REQUESTED'
  | 'HUMAN_APPROVAL_GRANTED'
  | 'HUMAN_APPROVAL_DENIED';

export interface AuditEvent {
  /** Monotonically increasing sequence number */
  sequenceNum: number;
  /** Unique event identifier */
  eventId: string;
  passportId: string;
  eventType: AuditEventType;
  severity: AttestationSeverity;
  /** Structured event payload */
  eventData: Record<string, unknown>;
  /** SHA-256 of the previous audit event (hash chain) */
  prevHash: string;
  /** SHA-256 of this event's content */
  rowHash: string;
  occurredAt: string;
}

// ─── Session (Trust Handshake) ────────────────────────────────────────────

export type SessionStatus = 'PENDING' | 'ESTABLISHED' | 'CLOSED' | 'FAILED';

export interface TrustSession {
  sessionId: string;
  initiatorPassportId: string;
  responderPassportId?: string;
  status: SessionStatus;
  establishedAt?: string;
  closedAt?: string;
  /** SHA-256 hash of the interaction result, provided on close */
  resultHash?: string;
  capabilityToken?: string;
  ttlSeconds: number;
}
