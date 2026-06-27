/**
 * Aegis Protocol SDK — Test Suite
 */

import { AegisClient } from '../index';

describe('AegisClient — Passport Issuance', () => {
  let aegis: AegisClient;

  beforeEach(() => {
    aegis = new AegisClient({
      orgId: 'org_test_001',
      orgName: 'Test Organization',
    });
  });

  test('issues a passport with correct structure', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'TestAgent',
      agentVersion: '1.0.0',
      modelFamily: 'claude-sonnet',
      deploymentEnv: 'production',
      permittedActions: ['read:data', 'write:reports'],
      deniedActions: ['delete:records'],
      requiresHumanApproval: [],
    });

    expect(passport.aegisVersion).toBe('1.0');
    expect(passport.passportId).toMatch(/^ap_[A-Za-z0-9]{26}$/);
    expect(passport.status).toBe('ACTIVE');
    expect(passport.subject.agentName).toBe('TestAgent');
    expect(passport.subject.organizationId).toBe('org_test_001');
    expect(passport.capabilities.permittedActions).toContain('read:data');
    expect(passport.capabilities.deniedActions).toContain('delete:records');
    expect(passport.signature.algorithm).toBe('ES256');
    expect(passport.signature.value).toBeTruthy();
  });

  test('assigns TRUSTED tier to production agents', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'ProdAgent',
      deploymentEnv: 'production',
      permittedActions: ['read:data'],
    });

    expect(passport.trustMetadata.trustTier).toBe('TRUSTED');
    expect(passport.trustMetadata.initialTrustScore).toBe(850);
  });

  test('assigns ELEVATED tier to staging agents', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'StagingAgent',
      deploymentEnv: 'staging',
      permittedActions: ['read:data'],
    });

    expect(passport.trustMetadata.trustTier).toBe('ELEVATED');
  });

  test('sets correct expiry date', async () => {
    const before = new Date();
    const passport = await aegis.passports.issue({
      agentName: 'Agent',
      permittedActions: ['read:data'],
      validityDays: 30,
    });
    const after = new Date();

    const expiresAt = new Date(passport.expiresAt);
    const expectedMin = new Date(before);
    expectedMin.setDate(expectedMin.getDate() + 30);
    const expectedMax = new Date(after);
    expectedMax.setDate(expectedMax.getDate() + 30);

    expect(expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMin.getTime());
    expect(expiresAt.getTime()).toBeLessThanOrEqual(expectedMax.getTime());
  });

  test('can retrieve issued passport by ID', async () => {
    const issued = await aegis.passports.issue({
      agentName: 'RetrievableAgent',
      permittedActions: ['read:data'],
    });

    const retrieved = await aegis.passports.get(issued.passportId);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.passportId).toBe(issued.passportId);
  });
});

describe('AegisClient — Verification', () => {
  let aegis: AegisClient;

  beforeEach(() => {
    aegis = new AegisClient({ orgId: 'org_verify_test', orgName: 'Verify Test Org' });
  });

  test('ALLOW: valid passport with permitted capability', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'AllowAgent',
      deploymentEnv: 'production',
      permittedActions: ['read:financial_data', 'write:reports'],
      deniedActions: [],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['read:financial_data'],
      riskLevel: 'LOW',
    });

    expect(result.decision).toBe('ALLOW');
    expect(result.trustScore).toBeGreaterThan(0);
    expect(result.capabilityToken).toBeTruthy();
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  test('DENY: passport not found', async () => {
    const result = await aegis.verify({
      passportId: 'ap_nonexistent0000000000000',
      requestedCapabilities: ['read:data'],
    });

    expect(result.decision).toBe('DENY');
    expect(result.capabilityToken).toBeUndefined();
  });

  test('DENY: explicitly denied capability', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'RestrictedAgent',
      permittedActions: ['read:data'],
      deniedActions: ['write:transactions'],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['write:transactions'],
    });

    expect(result.decision).toBe('DENY');
  });

  test('DENY: capability not in permitted scope', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'LimitedAgent',
      permittedActions: ['read:data'],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['delete:records'],
    });

    expect(result.decision).toBe('DENY');
  });

  test('DENY: revoked passport', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'RevokedAgent',
      permittedActions: ['read:data'],
    });

    await aegis.passports.revoke({
      passportId: passport.passportId,
      reason: 'SECURITY_INCIDENT',
      notes: 'Test revocation',
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['read:data'],
    });

    expect(result.decision).toBe('DENY');
  });

  test('REVIEW: requires human approval', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'ApprovalAgent',
      permittedActions: ['call:external_api'],
      requiresHumanApproval: ['call:external_api'],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['call:external_api'],
      riskLevel: 'MEDIUM',
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.warnings.some(w => w.includes('Human approval required'))).toBe(true);
  });

  test('result includes score components', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'ScoredAgent',
      permittedActions: ['read:data'],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['read:data'],
    });

    expect(result.scoreComponents.identity).toBeGreaterThanOrEqual(0);
    expect(result.scoreComponents.behavioral).toBeGreaterThanOrEqual(0);
    expect(result.scoreComponents.compliance).toBeGreaterThanOrEqual(0);
    expect(result.scoreComponents.historical).toBeGreaterThanOrEqual(0);
    expect(result.scoreComponents.environmental).toBeGreaterThanOrEqual(0);
  });

  test('audit receipt is returned', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'AuditedAgent',
      permittedActions: ['read:data'],
    });

    const result = await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['read:data'],
    });

    expect(result.auditReceiptId).toBeTruthy();
  });
});

describe('AegisClient — Audit Trail', () => {
  let aegis: AegisClient;

  beforeEach(() => {
    aegis = new AegisClient({ orgId: 'org_audit_test', orgName: 'Audit Test Org' });
  });

  test('audit log is populated after issuance and verification', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'AuditAgent',
      permittedActions: ['read:data'],
    });

    await aegis.verify({
      passportId: passport.passportId,
      requestedCapabilities: ['read:data'],
    });

    const log = await aegis.audit.getLog(passport.passportId);
    expect(log.length).toBeGreaterThanOrEqual(2);
    expect(log.some(e => e.eventType === 'PASSPORT_ISSUED')).toBe(true);
    expect(log.some(e => e.eventType === 'VERIFICATION_ALLOW' || e.eventType === 'VERIFICATION_DENY')).toBe(true);
  });

  test('audit chain integrity passes on clean log', async () => {
    await aegis.passports.issue({
      agentName: 'IntegrityAgent',
      permittedActions: ['read:data'],
    });

    const result = await aegis.audit.verifyIntegrity();
    expect(result.valid).toBe(true);
  });
});

describe('AegisClient — Revocation', () => {
  let aegis: AegisClient;

  beforeEach(() => {
    aegis = new AegisClient({ orgId: 'org_revoke_test', orgName: 'Revoke Test Org' });
  });

  test('revokes a passport and updates status', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'ToBeRevoked',
      permittedActions: ['read:data'],
    });

    const revoked = await aegis.passports.revoke({
      passportId: passport.passportId,
      reason: 'DECOMMISSIONED',
    });

    expect(revoked.status).toBe('REVOKED');
    expect(revoked.revokedAt).toBeTruthy();
    expect(revoked.revocationReason).toBe('DECOMMISSIONED');
  });

  test('cannot revoke an already-revoked passport', async () => {
    const passport = await aegis.passports.issue({
      agentName: 'DoubleRevoke',
      permittedActions: ['read:data'],
    });

    await aegis.passports.revoke({ passportId: passport.passportId, reason: 'DECOMMISSIONED' });

    await expect(
      aegis.passports.revoke({ passportId: passport.passportId, reason: 'POLICY_VIOLATION' })
    ).rejects.toThrow('already revoked');
  });
});
