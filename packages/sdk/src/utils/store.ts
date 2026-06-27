/**
 * Aegis Protocol SDK — In-Memory Store
 * 
 * Reference implementation storage layer.
 * 
 * PRODUCTION NOTE: Replace this with a real database (PostgreSQL recommended).
 * The store interface is designed to make swapping backends straightforward.
 */

import type { AegisPassport, AuditEvent, AttestationResponse, TrustSession } from '@aegis-protocol/spec';

// ─── Store Interface ───────────────────────────────────────────────────────

export interface PassportStore {
  save(passport: AegisPassport): Promise<void>;
  findById(passportId: string): Promise<AegisPassport | null>;
  findByOrgId(orgId: string): Promise<AegisPassport[]>;
  update(passportId: string, updates: Partial<AegisPassport>): Promise<AegisPassport | null>;
}

export interface AuditStore {
  /** Append-only. Returns false if tampering is detected. */
  append(event: AuditEvent): Promise<boolean>;
  findByPassportId(passportId: string, limit?: number): Promise<AuditEvent[]>;
  /** Verify the integrity of the hash chain */
  verifyChain(passportId: string): Promise<boolean>;
  getLatestHash(): Promise<string>;
}

export interface SessionStore {
  save(session: TrustSession): Promise<void>;
  findById(sessionId: string): Promise<TrustSession | null>;
  update(sessionId: string, updates: Partial<TrustSession>): Promise<void>;
}

// ─── In-Memory Implementation ──────────────────────────────────────────────

export class InMemoryPassportStore implements PassportStore {
  private passports = new Map<string, AegisPassport>();

  async save(passport: AegisPassport): Promise<void> {
    this.passports.set(passport.passportId, { ...passport });
  }

  async findById(passportId: string): Promise<AegisPassport | null> {
    return this.passports.get(passportId) ?? null;
  }

  async findByOrgId(orgId: string): Promise<AegisPassport[]> {
    return Array.from(this.passports.values()).filter(
      p => p.subject.organizationId === orgId
    );
  }

  async update(passportId: string, updates: Partial<AegisPassport>): Promise<AegisPassport | null> {
    const existing = this.passports.get(passportId);
    if (!existing) return null;
    const updated = { ...existing, ...updates };
    this.passports.set(passportId, updated);
    return updated;
  }
}

export class InMemoryAuditStore implements AuditStore {
  private events: AuditEvent[] = [];
  private genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

  async append(event: AuditEvent): Promise<boolean> {
    // Verify the prevHash links to our last event
    const expectedPrevHash = this.events.length === 0
      ? this.genesisHash
      : this.events[this.events.length - 1].rowHash;

    if (event.prevHash !== expectedPrevHash) {
      return false; // Chain broken — reject
    }

    this.events.push({ ...event });
    return true;
  }

  async findByPassportId(passportId: string, limit = 50): Promise<AuditEvent[]> {
    return this.events
      .filter(e => e.passportId === passportId)
      .slice(-limit)
      .reverse();
  }

  async verifyChain(_passportId: string): Promise<boolean> {
    // Verify the entire chain from genesis
    let prevHash = this.genesisHash;
    for (const event of this.events) {
      if (event.prevHash !== prevHash) return false;
      prevHash = event.rowHash;
    }
    return true;
  }

  async getLatestHash(): Promise<string> {
    if (this.events.length === 0) return this.genesisHash;
    return this.events[this.events.length - 1].rowHash;
  }
}

export class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, TrustSession>();

  async save(session: TrustSession): Promise<void> {
    this.sessions.set(session.sessionId, { ...session });
  }

  async findById(sessionId: string): Promise<TrustSession | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async update(sessionId: string, updates: Partial<TrustSession>): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      this.sessions.set(sessionId, { ...existing, ...updates });
    }
  }
}
