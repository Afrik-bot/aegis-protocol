/**
 * Aegis Protocol SDK — Trust Score Engine
 *
 * Implements the Aegis Trust Score Algorithm v1.0:
 *
 *   T(a) = w1·I(a) + w2·B(a) + w3·C(a) + w4·H(a) + w5·E(a)
 *
 * Where:
 *   I(a) = Identity confidence          [0–1000]
 *   B(a) = Behavioral baseline adherence [0–1000]
 *   C(a) = Compliance posture           [0–1000]
 *   H(a) = Historical record            [0–1000]
 *   E(a) = Environmental risk           [0–1000]
 */

import type { AegisPassport, TrustScoreComponents, RiskLevel } from '@aegis-protocol/spec';
import {
  TRUST_SCORE_WEIGHTS,
  TRUST_SCORE_MIN,
  TRUST_SCORE_MAX,
  HISTORICAL_HALF_LIFE_DAYS,
  TRUST_TIER_THRESHOLDS,
} from '@aegis-protocol/spec';
import type { AuditStore } from '../utils/store';

// ─── I(a) — Identity Confidence ───────────────────────────────────────────

interface IdentitySignals {
  /** Is the certificate chain valid and unrevoked? */
  certificateValid: boolean;
  /** Is the private key stored in an HSM? */
  hsmBacked: boolean;
  /** Days since last key rotation */
  daysSinceKeyRotation: number;
  /** Age of the most recent OCSP response in minutes */
  ocspAgeMinutes: number;
}

function computeIdentityScore(signals: IdentitySignals): number {
  if (!signals.certificateValid) return 0; // Hard floor — invalid cert = zero

  let score = 400; // Base for valid cert chain

  // HSM backing
  if (signals.hsmBacked) score += 250;
  else score += 150; // Software key

  // Key rotation recency
  if (signals.daysSinceKeyRotation < 90) score += 200;
  else if (signals.daysSinceKeyRotation < 180) score += 100;

  // OCSP freshness
  if (signals.ocspAgeMinutes < 15) score += 150;
  else if (signals.ocspAgeMinutes < 60) score += 75;

  return Math.min(score, TRUST_SCORE_MAX);
}

// ─── B(a) — Behavioral Baseline Adherence ─────────────────────────────────

interface BehavioralSignals {
  /**
   * Similarity score between current behavior and declared baseline.
   * 1.0 = identical, 0.0 = completely different.
   */
  baselineSimilarity: number;
  /** Has the agent exceeded any capability scope recently? */
  recentScopeViolation: boolean;
}

function computeBehavioralScore(signals: BehavioralSignals): number {
  if (signals.recentScopeViolation) return 200; // Significant penalty for violations

  // Linear mapping from similarity [0,1] → [200, 1000]
  return Math.round(200 + (signals.baselineSimilarity * 800));
}

// ─── C(a) — Compliance Posture ─────────────────────────────────────────────

interface ComplianceSignals {
  /** Fraction of policy checkpoints passed in the last 30 days [0,1] */
  checkpointPassRate: number;
  /** Are all required human approvals being obtained? */
  humanApprovalCompliant: boolean;
  /** Does the passport have a valid policy framework reference? */
  hasPolicyFramework: boolean;
}

function computeComplianceScore(signals: ComplianceSignals): number {
  let score = Math.round(signals.checkpointPassRate * 700); // Up to 700 from pass rate

  if (signals.humanApprovalCompliant) score += 200;
  if (signals.hasPolicyFramework) score += 100;

  return Math.min(score, TRUST_SCORE_MAX);
}

// ─── H(a) — Historical Record ─────────────────────────────────────────────

interface HistoricalEvent {
  /** Impact score: positive for good events, negative for incidents */
  impact: number;
  /** Date of event */
  occurredAt: Date;
}

/**
 * Time-decayed historical score.
 * H(a,t) = Σ s_i · e^(-λ(t - t_i))   where λ = ln(2)/90 (90-day half-life)
 */
function computeHistoricalScore(events: HistoricalEvent[]): number {
  const lambda = Math.LN2 / HISTORICAL_HALF_LIFE_DAYS;
  const now = Date.now();
  const MS_PER_DAY = 86400000;

  let rawScore = events.reduce((sum, event) => {
    const ageDays = (now - event.occurredAt.getTime()) / MS_PER_DAY;
    return sum + event.impact * Math.exp(-lambda * ageDays);
  }, 0);

  // Normalize to [0, 1000], centered at 700 (default for no events)
  const baseScore = 700;
  const clamped = Math.max(TRUST_SCORE_MIN, Math.min(TRUST_SCORE_MAX, baseScore + rawScore));
  return Math.round(clamped);
}

// ─── E(a) — Environmental Risk ────────────────────────────────────────────

interface EnvironmentalSignals {
  deploymentEnv: string;
  riskLevel: RiskLevel;
  jurisdiction: string;
}

function computeEnvironmentalScore(signals: EnvironmentalSignals): number {
  let score = 1000;

  // Deployment environment penalty
  if (signals.deploymentEnv === 'development') score -= 300;
  else if (signals.deploymentEnv === 'staging') score -= 150;

  // Risk level penalty
  const riskPenalties: Record<RiskLevel, number> = {
    LOW: 0, MEDIUM: 50, HIGH: 150, CRITICAL: 300,
  };
  score -= riskPenalties[signals.riskLevel] ?? 0;

  return Math.max(TRUST_SCORE_MIN, score);
}

// ─── Composite Score ──────────────────────────────────────────────────────

export interface TrustScoreInput {
  passport: AegisPassport;
  riskLevel: RiskLevel;
  /** Behavioral signals from runtime monitoring */
  behavioral?: Partial<BehavioralSignals>;
  /** Historical events from the audit log */
  historicalEvents?: HistoricalEvent[];
}

export function computeTrustScore(input: TrustScoreInput): {
  score: number;
  tier: AegisPassport['trustMetadata']['trustTier'];
  components: TrustScoreComponents;
} {
  const { passport, riskLevel } = input;

  // Identity signals — in a production system these come from the PKI layer
  const identitySignals: IdentitySignals = {
    certificateValid: passport.status === 'ACTIVE',
    hsmBacked: false, // Reference implementation uses software keys
    daysSinceKeyRotation: 30, // Would be derived from cert metadata
    ocspAgeMinutes: 5,        // Would be fetched from OCSP responder
  };

  const behavioralSignals: BehavioralSignals = {
    baselineSimilarity: input.behavioral?.baselineSimilarity ?? 0.95,
    recentScopeViolation: input.behavioral?.recentScopeViolation ?? false,
  };

  const complianceSignals: ComplianceSignals = {
    checkpointPassRate: 1.0,
    humanApprovalCompliant: true,
    hasPolicyFramework: !!passport.trustMetadata.policyFramework,
  };

  const historicalEvents = input.historicalEvents ?? [];

  const environmentalSignals: EnvironmentalSignals = {
    deploymentEnv: passport.subject.deploymentEnv,
    riskLevel,
    jurisdiction: passport.subject.jurisdiction,
  };

  const components: TrustScoreComponents = {
    identity:     computeIdentityScore(identitySignals),
    behavioral:   computeBehavioralScore(behavioralSignals),
    compliance:   computeComplianceScore(complianceSignals),
    historical:   computeHistoricalScore(historicalEvents),
    environmental: computeEnvironmentalScore(environmentalSignals),
  };

  const w = TRUST_SCORE_WEIGHTS;
  const raw =
    w.identity      * components.identity     +
    w.behavioral    * components.behavioral   +
    w.compliance    * components.compliance   +
    w.historical    * components.historical   +
    w.environmental * components.environmental;

  const score = Math.round(Math.max(TRUST_SCORE_MIN, Math.min(TRUST_SCORE_MAX, raw)));

  const tier =
    score >= TRUST_TIER_THRESHOLDS.TRUSTED  ? 'TRUSTED'  :
    score >= TRUST_TIER_THRESHOLDS.ELEVATED ? 'ELEVATED' :
    score >= TRUST_TIER_THRESHOLDS.STANDARD ? 'STANDARD' :
    score >= TRUST_TIER_THRESHOLDS.LOW      ? 'LOW'      :
    'CRITICAL';

  return { score, tier, components };
}
