
import { describe, it, expect, vi } from 'vitest';
import { X448PublicKeyParts } from '../../../../models/packets/keyData/X448PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('X448PublicKeyParts', () => {
    const keyboxData = new Uint8Array(100); // Dummy larger buffer
    const expectedLength = 56;

    it('should parse a valid X448 public key correctly', () => {
        const publicKeyHex = 'AB'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);

        keyboxData.set(publicKeyData, 0);
        const x448Parts = new X448PublicKeyParts(keyboxData, 0, publicKeyData.length);

        expect(x448Parts.publicKey).toEqual(publicKeyData);
        expect(x448Parts.totalLength).toBe(expectedLength);
    });

    it('should produce correct JSON output', () => {
        const publicKeyHex = 'CD'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        
        keyboxData.set(publicKeyData, 0);
        const x448Parts = new X448PublicKeyParts(keyboxData, 0, publicKeyData.length);
        const json = x448Parts.toJSON();

        expect(json.publicKey_hex).toBe(publicKeyHex.toLowerCase());
        expect(json.totalLength).toBe(expectedLength);
    });

    it('should throw if data length is less than expected', () => {
        const shortKeyData = hexToUint8Array('00'.repeat(expectedLength - 1));
        keyboxData.set(shortKeyData, 0);
        
        expect(() => new X448PublicKeyParts(keyboxData, 0, shortKeyData.length))
            .toThrow(`X448PublicKeyParts: Data length (${expectedLength - 1}) is less than expected ${expectedLength} bytes.`);
    });
    
    it('should handle public key data at an offset', () => {
        const publicKeyHex = '1A'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        const offset = 10;

        keyboxData.set(publicKeyData, offset);
        const x448Parts = new X448PublicKeyParts(keyboxData, offset, publicKeyData.length);

        expect(x448Parts.publicKey).toEqual(publicKeyData);
        expect(x448Parts.totalLength).toBe(expectedLength);
    });
});
