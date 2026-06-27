/**
 * Aegis Protocol — Basic Usage Example
 *
 * Demonstrates the core workflow:
 *   1. Create a client
 *   2. Issue an AI Passport
 *   3. Verify the agent before a sensitive action
 *   4. Revoke if something goes wrong
 */

// In your project: import { AegisClient } from '@aegis-protocol/sdk';
const path = require('path');
const { AegisClient } = require(path.join(__dirname, '../packages/sdk/src/index'));

async function main() {
  // ── 1. Initialize the Aegis client ──────────────────────────────────────
  const aegis = new AegisClient({
    orgId: 'org_acme_financial_001',
    orgName: 'ACME Financial Services LLC',
  });

  console.log('✓ Aegis client initialized\n');

  // ── 2. Issue a passport for your AI agent ──────────────────────────────
  console.log('Issuing AI Passport for AnalysisAgent-v2...');

  const passport = await aegis.passports.issue({
    agentName: 'AnalysisAgent-v2',
    agentVersion: '2.4.1',
    modelFamily: 'claude-sonnet',
    deploymentEnv: 'production',
    jurisdiction: 'US',
    permittedActions: [
      'read:financial_data',
      'write:reports',
    ],
    deniedActions: [
      'write:transactions',
      'delete:records',
    ],
    requiresHumanApproval: [
      'call:external_api',
    ],
  });

  console.log(`✓ Passport issued: ${passport.passportId}`);
  console.log(`  Agent:      ${passport.subject.agentName} v${passport.subject.agentVersion}`);
  console.log(`  Trust tier: ${passport.trustMetadata.trustTier} (${passport.trustMetadata.initialTrustScore}/1000)`);
  console.log(`  Expires:    ${new Date(passport.expiresAt).toLocaleDateString()}\n`);

  // ── 3. Verify before a sensitive interaction ────────────────────────────
  console.log('Verifying agent before accessing financial data...');

  const decision = await aegis.verify({
    passportId: passport.passportId,
    requestedCapabilities: ['read:financial_data'],
    interactionType: 'data_access',
    riskLevel: 'HIGH',
    relyingParty: 'risk-reporting-system',
  });

  console.log(`✓ Trust decision: ${decision.decision}`);
  console.log(`  Trust score:    ${decision.trustScore}/1000 (${decision.trustTier})`);
  console.log(`  Latency:        ${decision.latencyMs}ms`);
  if (decision.capabilityToken) {
    console.log(`  Capability token: ${decision.capabilityToken.slice(0, 40)}...`);
  }
  if (decision.warnings.length > 0) {
    console.log(`  Warnings: ${decision.warnings.join(', ')}`);
  }
  console.log();

  // ── 4. Verify a denied capability ──────────────────────────────────────
  console.log('Attempting to verify a denied capability (write:transactions)...');

  const deniedDecision = await aegis.verify({
    passportId: passport.passportId,
    requestedCapabilities: ['write:transactions'],
    riskLevel: 'CRITICAL',
  });

  console.log(`✓ Trust decision: ${deniedDecision.decision} (expected DENY)`);
  console.log(`  Reason: ${deniedDecision.warnings[0]}\n`);

  // ── 5. Submit a behavioral attestation ─────────────────────────────────
  console.log('Submitting behavioral attestation...');

  const attestation = await aegis.attest({
    passportId: passport.passportId,
    attestationType: 'POLICY_CHECKPOINT',
    severity: 'INFO',
    evidence: {
      checkpoint: 'quarterly_compliance_review',
      result: 'PASSED',
      reviewedBy: 'ComplianceSystem-v1',
      timestamp: new Date().toISOString(),
    },
  });

  console.log(`✓ Attestation recorded: ${attestation.attestationId}`);
  console.log(`  Trust score delta: +${attestation.trustScoreDelta}\n`);

  // ── 6. View audit log ─────────────────────────────────────────────────
  console.log('Fetching audit log...');

  const auditLog = await aegis.audit.getLog(passport.passportId);
  console.log(`✓ ${auditLog.length} audit events recorded:`);
  auditLog.forEach(event => {
    console.log(`  [${event.severity}] ${event.eventType} — ${event.occurredAt}`);
  });
  console.log();

  // ── 7. Verify chain integrity ─────────────────────────────────────────
  const integrity = await aegis.audit.verifyIntegrity();
  console.log(`✓ Audit chain integrity: ${integrity.message}\n`);

  // ── 8. Revoke in an emergency ─────────────────────────────────────────
  console.log('Simulating security incident — revoking passport...');

  const revoked = await aegis.passports.revoke({
    passportId: passport.passportId,
    reason: 'SECURITY_INCIDENT',
    notes: 'Anomalous data access pattern detected by monitoring system',
  });

  console.log(`✓ Passport revoked: ${revoked.passportId}`);
  console.log(`  Status:    ${revoked.status}`);
  console.log(`  Revoked:   ${revoked.revokedAt}`);
  console.log(`  Reason:    ${revoked.revocationReason}\n`);

  // ── 9. Verify the revoked agent is denied ────────────────────────────
  const postRevoke = await aegis.verify({
    passportId: passport.passportId,
    requestedCapabilities: ['read:financial_data'],
  });

  console.log(`✓ Post-revocation decision: ${postRevoke.decision} (expected DENY)`);
  console.log('\nDone. Trust. Verified. Every AI Agent.');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
