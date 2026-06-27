/**
 * Aegis Protocol v1.0 — Constants
 * 
 * Normative values defined by the protocol specification.
 * Implementations MUST use these values unless explicitly noted as configurable.
 */

export const AEGIS_VERSION = '1.0' as const;

// ─── Passport ID ──────────────────────────────────────────────────────────
/** Prefix for all AI Passport identifiers */
export const PASSPORT_ID_PREFIX = 'ap_' as const;
/** Length of the random suffix after the prefix */
export const PASSPORT_ID_SUFFIX_LENGTH = 26;

// ─── Agent ID ─────────────────────────────────────────────────────────────
export const AGENT_ID_PREFIX = 'agt_' as const;
export const AGENT_ID_SUFFIX_LENGTH = 32;

// ─── Trust Score ──────────────────────────────────────────────────────────
export const TRUST_SCORE_MIN = 0;
export const TRUST_SCORE_MAX = 1000;

/** Trust tier thresholds (inclusive lower bound) */
export const TRUST_TIER_THRESHOLDS = {
  TRUSTED:  850,
  ELEVATED: 650,
  STANDARD: 400,
  LOW:      200,
  CRITICAL: 0,
} as const;

/**
 * Default weights for the composite trust score formula:
 * T(a) = w1·I(a) + w2·B(a) + w3·C(a) + w4·H(a) + w5·E(a)
 * 
 * Weights sum to 1.0.
 */
export const TRUST_SCORE_WEIGHTS = {
  identity:     0.30,  // I(a) — identity confidence
  behavioral:   0.25,  // B(a) — behavioral baseline adherence
  compliance:   0.20,  // C(a) — compliance posture
  historical:   0.15,  // H(a) — historical incident-free record
  environmental: 0.10, // E(a) — environmental risk adjustment
} as const;

/**
 * Historical score decay half-life in days.
 * λ = ln(2) / HISTORICAL_HALF_LIFE_DAYS
 * H(a,t) = Σ s_i · e^(-λ(t - t_i))
 */
export const HISTORICAL_HALF_LIFE_DAYS = 90;

// ─── Capability Token ─────────────────────────────────────────────────────
/** Default TTL for capability tokens in seconds (15 minutes) */
export const CAPABILITY_TOKEN_DEFAULT_TTL_SECONDS = 900;
/** Maximum TTL for capability tokens in seconds (1 hour) */
export const CAPABILITY_TOKEN_MAX_TTL_SECONDS = 3600;

// ─── Passport Lifecycle ───────────────────────────────────────────────────
/** Default passport validity period in days */
export const PASSPORT_DEFAULT_VALIDITY_DAYS = 365;
/** Maximum passport validity period in days */
export const PASSPORT_MAX_VALIDITY_DAYS = 365;

// ─── Revocation ───────────────────────────────────────────────────────────
/** Maximum seconds for revocation to propagate to all nodes */
export const REVOCATION_MAX_PROPAGATION_SECONDS = 60;

// ─── Verification SLA ─────────────────────────────────────────────────────
/** Target p99 latency for trust decisions in milliseconds */
export const VERIFICATION_TARGET_LATENCY_MS = 50;

// ─── Audit ────────────────────────────────────────────────────────────────
/** Hashing algorithm for audit log chain */
export const AUDIT_HASH_ALGORITHM = 'sha256' as const;

// ─── Cryptography ─────────────────────────────────────────────────────────
export const SUPPORTED_SIGNATURE_ALGORITHMS = ['ES256', 'ES384'] as const;
export const DEFAULT_SIGNATURE_ALGORITHM = 'ES256' as const;

// ─── Action Scope ─────────────────────────────────────────────────────────
/**
 * Well-known action scope prefixes.
 * Custom scopes SHOULD follow the "verb:resource" convention.
 */
export const WELL_KNOWN_ACTIONS = {
  READ_ANY:          'read:*',
  WRITE_ANY:         'write:*',
  DELETE_ANY:        'delete:*',
  READ_FINANCIAL:    'read:financial_data',
  WRITE_FINANCIAL:   'write:financial_data',
  WRITE_TRANSACTION: 'write:transactions',
  READ_PII:          'read:pii',
  WRITE_PII:         'write:pii',
  READ_AUDIT:        'read:audit_logs',
  CALL_EXTERNAL_API: 'call:external_api',
  SEND_EMAIL:        'send:email',
  WRITE_REPORTS:     'write:reports',
  READ_POLICIES:     'read:policies',
  WRITE_POLICIES:    'write:policies',
} as const;

// ─── Trust Score Impact of Events ─────────────────────────────────────────
/** Score deltas applied when attestation events are recorded */
export const TRUST_SCORE_EVENT_IMPACT = {
  // Positive events
  CLEAN_INTERACTION:        +10,
  POLICY_CHECKPOINT_PASSED: +15,
  HUMAN_APPROVAL_GRANTED:   +5,

  // Negative events
  POLICY_VIOLATION:         -150,
  CAPABILITY_EXCEEDED:      -200,
  SECURITY_INCIDENT:        -500,
  HUMAN_APPROVAL_DENIED:    -50,
  BEHAVIORAL_DRIFT_MINOR:   -30,
  BEHAVIORAL_DRIFT_MAJOR:   -100,
} as const;
