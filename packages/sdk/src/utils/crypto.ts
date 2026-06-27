/**
 * Aegis Protocol SDK — Cryptographic Utilities
 * 
 * IMPORTANT: This is a reference implementation using Node.js built-in crypto.
 * For production deployments, replace signing operations with HSM-backed keys.
 */

import { createHash, generateKeyPairSync, createSign, createVerify, randomBytes } from 'crypto';
import type { SignatureAlgorithm } from '@aegis-protocol/spec';
import {
  PASSPORT_ID_PREFIX,
  PASSPORT_ID_SUFFIX_LENGTH,
  AGENT_ID_PREFIX,
  AGENT_ID_SUFFIX_LENGTH,
  AUDIT_HASH_ALGORITHM,
} from '@aegis-protocol/spec';

const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/**
 * Generate a cryptographically random alphanumeric ID.
 * Uses rejection sampling to ensure uniform distribution.
 */
export function randomId(length: number): string {
  const result: string[] = [];
  while (result.length < length) {
    const bytes = randomBytes(length * 2);
    for (const byte of bytes) {
      if (result.length >= length) break;
      const index = byte % 62;
      // Reject if byte >= 248 to ensure uniform distribution (248 = floor(256/62)*62)
      if (byte < 248) result.push(ALPHABET[index]);
    }
  }
  return result.join('');
}

export function generatePassportId(): string {
  return `${PASSPORT_ID_PREFIX}${randomId(PASSPORT_ID_SUFFIX_LENGTH)}`;
}

export function generateAgentId(): string {
  return `${AGENT_ID_PREFIX}${randomBytes(16).toString('hex')}`;
}

export function generateEventId(): string {
  return `evt_${randomId(24)}`;
}

export function generateAuditReceiptId(): string {
  return `ar_${randomId(24)}`;
}

export function generateAttestationId(): string {
  return `att_${randomId(24)}`;
}

export function generateSessionId(): string {
  return `sess_${randomId(24)}`;
}

/**
 * Compute SHA-256 hash of a string or object.
 * Returns hex-encoded digest.
 */
export function sha256(input: string | object): string {
  const data = typeof input === 'string' ? input : JSON.stringify(input);
  return createHash(AUDIT_HASH_ALGORITHM).update(data, 'utf8').digest('hex');
}

/**
 * Canonical JSON serialization for signing.
 * Keys are sorted to ensure deterministic output.
 */
export function canonicalize(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ─── Key Pair (Reference Implementation) ─────────────────────────────────

export interface KeyPair {
  publicKey: string;   // PEM
  privateKey: string;  // PEM — in production, this never leaves the HSM
  keyId: string;
  algorithm: SignatureAlgorithm;
}

/**
 * Generate an ECDSA key pair for signing passports.
 * 
 * PRODUCTION NOTE: In a real deployment, key generation and storage
 * must occur inside a Hardware Security Module (HSM). The private key
 * should never be exported or accessible to application code.
 */
export function generateKeyPair(algorithm: SignatureAlgorithm = 'ES256'): KeyPair {
  const namedCurve = algorithm === 'ES256' ? 'prime256v1' : 'secp384r1';
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return {
    publicKey: publicKey as string,
    privateKey: privateKey as string,
    keyId: `kid_${randomId(16)}`,
    algorithm,
  };
}

/**
 * Sign a payload with a private key.
 * Returns base64url-encoded signature.
 */
export function sign(payload: object, privateKeyPem: string, algorithm: SignatureAlgorithm = 'ES256'): string {
  const hashAlg = algorithm === 'ES256' ? 'SHA256' : 'SHA384';
  const signer = createSign(hashAlg);
  signer.update(canonicalize(payload));
  signer.end();
  return signer.sign(privateKeyPem, 'base64url');
}

/**
 * Verify a signature over a payload.
 */
export function verifySignature(
  payload: object,
  signature: string,
  publicKeyPem: string,
  algorithm: SignatureAlgorithm = 'ES256'
): boolean {
  try {
    const hashAlg = algorithm === 'ES256' ? 'SHA256' : 'SHA384';
    const verifier = createVerify(hashAlg);
    verifier.update(canonicalize(payload));
    verifier.end();
    return verifier.verify(publicKeyPem, signature, 'base64url');
  } catch {
    return false;
  }
}

/**
 * Generate a mock self-signed PEM certificate for the reference implementation.
 * 
 * PRODUCTION NOTE: Real certificates must be issued by the Aegis Certificate
 * Authority chain (Root CA → Intermediate CA → Issuing CA).
 */
export function mockCertificate(keyId: string): string {
  // A real implementation would perform a CSR + CA signing ceremony.
  // For the reference verifier, we use a placeholder PEM structure.
  const placeholder = Buffer.from(
    `AEGIS-REFERENCE-CERT:${keyId}:${Date.now()}`
  ).toString('base64');
  return `-----BEGIN CERTIFICATE-----\n${placeholder}\n-----END CERTIFICATE-----`;
}
