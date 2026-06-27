/**
 * Aegis Protocol SDK — Audit Trail
 *
 * Implements the AUDIT primitive: append-only, hash-chained event log.
 * Every event is linked to its predecessor via SHA-256, making
 * any retrospective tampering detectable.
 */

import type { AuditEvent, AuditEventType, AttestationSeverity } from '@aegis-protocol/spec';
import { sha256, canonicalize, generateEventId } from '../utils/crypto';
import type { AuditStore } from '../utils/store';

let sequenceCounter = 0;

interface AppendInput {
  passportId: string;
  eventType: AuditEventType;
  severity: AttestationSeverity;
  eventData: Record<string, unknown>;
}

export async function appendAuditEvent(
  store: AuditStore,
  input: AppendInput
): Promise<AuditEvent> {
  const prevHash = await store.getLatestHash();
  const eventId = generateEventId();
  const occurredAt = new Date().toISOString();
  const sequenceNum = ++sequenceCounter;

  // Build the row content for hashing (excludes rowHash itself)
  const rowContent = {
    sequenceNum,
    eventId,
    passportId: input.passportId,
    eventType: input.eventType,
    severity: input.severity,
    eventData: input.eventData,
    prevHash,
    occurredAt,
  };

  const rowHash = sha256(canonicalize(rowContent));

  const event: AuditEvent = {
    ...rowContent,
    rowHash,
  };

  const accepted = await store.append(event);
  if (!accepted) {
    throw new Error(
      `Audit chain integrity failure: event ${eventId} rejected. ` +
      'This may indicate concurrent writes or chain tampering.'
    );
  }

  return event;
}

export async function getAuditLog(
  passportId: string,
  store: AuditStore,
  limit = 50
): Promise<AuditEvent[]> {
  return store.findByPassportId(passportId, limit);
}

export async function verifyAuditChainIntegrity(store: AuditStore): Promise<{
  valid: boolean;
  message: string;
}> {
  const valid = await store.verifyChain('*');
  return {
    valid,
    message: valid
      ? 'Audit chain integrity verified — no tampering detected'
      : 'INTEGRITY FAILURE: Hash chain is broken. Audit log may have been tampered with.',
  };
}
