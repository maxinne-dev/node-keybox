import { describe, it, expect } from 'vitest';
import { Ed448PublicKeyParts } from '../../../../models/packets/keyData/Ed448PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';

describe('Ed448PublicKeyParts', () => {
    const validKeyboxData = hexToUint8Array('00'.repeat(100) + '04'.repeat(57)); // 57 bytes public key

    it('should parse valid Ed448 public key data', () => {
        const instance = new Ed448PublicKeyParts(validKeyboxData, 100, 57);
        expect(instance.publicKey).toEqual(hexToUint8Array('04'.repeat(57)));
        expect(instance.totalLength).toBe(57);
    });

    it('should throw if data length is less than expected', () => {
        expect(() => new Ed448PublicKeyParts(validKeyboxData, 100, 56)).toThrow(
            'Ed448PublicKeyParts: Data length (56) is less than expected 57 bytes.'
        );
    });

    it('should produce correct JSON output', () => {
        const instance = new Ed448PublicKeyParts(validKeyboxData, 100, 57);
        const json = instance.toJSON();
        expect(json.publicKey_hex).toBe('04'.repeat(57));
        expect(json.totalLength).toBe(57);
    });
});
