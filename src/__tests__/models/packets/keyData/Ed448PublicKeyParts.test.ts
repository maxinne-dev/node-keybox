
import { describe, it, expect, vi } from 'vitest';
import { Ed448PublicKeyParts } from '../../../../models/packets/keyData/Ed448PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('Ed448PublicKeyParts', () => {
    const keyboxData = new Uint8Array(100); // Dummy larger buffer
    const expectedLength = 57; // RFC 9580, Section 5.5.5.10 specifies 57 octets

    it('should parse a valid Ed448 public key correctly', () => {
        const publicKeyHex = 'AB'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);

        keyboxData.set(publicKeyData, 0);
        const edParts = new Ed448PublicKeyParts(keyboxData, 0, publicKeyData.length);

        expect(edParts.publicKey).toEqual(publicKeyData);
        expect(edParts.totalLength).toBe(expectedLength);
    });

    it('should produce correct JSON output', () => {
        const publicKeyHex = 'CD'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        
        keyboxData.set(publicKeyData, 0);
        const edParts = new Ed448PublicKeyParts(keyboxData, 0, publicKeyData.length);
        const json = edParts.toJSON();

        expect(json.publicKey_hex).toBe(publicKeyHex.toLowerCase());
        expect(json.totalLength).toBe(expectedLength);
    });

    it('should throw if data length is less than expected', () => {
        const shortKeyData = hexToUint8Array('00'.repeat(expectedLength - 1));
        keyboxData.set(shortKeyData, 0);
        
        expect(() => new Ed448PublicKeyParts(keyboxData, 0, shortKeyData.length))
            .toThrow(`Ed448PublicKeyParts: Data length (${expectedLength - 1}) is less than expected ${expectedLength} bytes.`);
    });

    it('should handle public key data at an offset', () => {
        const publicKeyHex = '1A'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        const offset = 10;

        keyboxData.set(publicKeyData, offset);
        const edParts = new Ed448PublicKeyParts(keyboxData, offset, publicKeyData.length);

        expect(edParts.publicKey).toEqual(publicKeyData);
        expect(edParts.totalLength).toBe(expectedLength);
    });
});
