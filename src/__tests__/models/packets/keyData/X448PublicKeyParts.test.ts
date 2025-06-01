import { describe, it, expect } from 'vitest';
import { X448PublicKeyParts } from '../../../../models/packets/keyData/X448PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';

describe('X448PublicKeyParts', () => {
    const validKeyboxData = hexToUint8Array('00'.repeat(100) + '01'.repeat(56)); // 56 bytes public key

    it('should parse valid X448 public key data', () => {
        const instance = new X448PublicKeyParts(validKeyboxData, 100, 56);
        expect(instance.publicKey).toEqual(hexToUint8Array('01'.repeat(56)));
        expect(instance.totalLength).toBe(56);
    });

    it('should throw if data length is less than expected', () => {
        expect(() => new X448PublicKeyParts(validKeyboxData, 100, 55)).toThrow(
            'X448PublicKeyParts: Data length (55) is less than expected 56 bytes.'
        );
    });

    it('should produce correct JSON output', () => {
        const instance = new X448PublicKeyParts(validKeyboxData, 100, 56);
        const json = instance.toJSON();
        expect(json.publicKey_hex).toBe('01'.repeat(56));
        expect(json.totalLength).toBe(56);
    });
});
