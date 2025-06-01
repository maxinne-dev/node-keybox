import { describe, it, expect } from 'vitest';
import { Ed25519PublicKeyParts } from '../../../../models/packets/keyData/Ed25519PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';

describe('Ed25519PublicKeyParts', () => {
    const validKeyboxData = hexToUint8Array('00'.repeat(100) + '05'.repeat(32)); // 32 bytes public key

    it('should parse valid Ed25519 public key data', () => {
        const instance = new Ed25519PublicKeyParts(validKeyboxData, 100, 32);
        expect(instance.publicKey).toEqual(hexToUint8Array('05'.repeat(32)));
        expect(instance.totalLength).toBe(32);
    });

    it('should throw if data length is less than expected', () => {
        expect(() => new Ed25519PublicKeyParts(validKeyboxData, 100, 31)).toThrow(
            'Ed25519PublicKeyParts: Data length (31) is less than expected 32 bytes.'
        );
    });

    it('should produce correct JSON output', () => {
        const instance = new Ed25519PublicKeyParts(validKeyboxData, 100, 32);
        const json = instance.toJSON();
        expect(json.publicKey_hex).toBe('05'.repeat(32));
        expect(json.totalLength).toBe(32);
    });
});
