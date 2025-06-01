
import { describe, it, expect, vi } from 'vitest';
import { X25519PublicKeyParts } from '../../../../models/packets/keyData/X25519PublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('X25519PublicKeyParts', () => {
    const keyboxData = new Uint8Array(100); // Dummy larger buffer
    const expectedLength = 32;

    it('should parse a valid X25519 public key correctly', () => {
        const publicKeyHex = 'AB'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);

        keyboxData.set(publicKeyData, 0);
        const x25519Parts = new X25519PublicKeyParts(keyboxData, 0, publicKeyData.length);

        expect(x25519Parts.publicKey).toEqual(publicKeyData);
        expect(x25519Parts.totalLength).toBe(expectedLength);
    });

    it('should produce correct JSON output', () => {
        const publicKeyHex = 'CD'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        
        keyboxData.set(publicKeyData, 0);
        const x25519Parts = new X25519PublicKeyParts(keyboxData, 0, publicKeyData.length);
        const json = x25519Parts.toJSON();

        expect(json.publicKey_hex).toBe(publicKeyHex.toLowerCase());
        expect(json.totalLength).toBe(expectedLength);
    });

    it('should throw if data length is less than expected', () => {
        const shortKeyData = hexToUint8Array('00'.repeat(expectedLength - 1));
        keyboxData.set(shortKeyData, 0);
        
        expect(() => new X25519PublicKeyParts(keyboxData, 0, shortKeyData.length))
            .toThrow(`X25519PublicKeyParts: Data length (${expectedLength - 1}) is less than expected ${expectedLength} bytes.`);
    });

    it('should parse correctly if data length is greater than expected (uses fixed length)', () => {
        // The constructor for X25519PublicKeyParts uses its fixed totalLength for slicing,
        // so extra data in the dataLength parameter doesn't cause a parse failure,
        // nor does it trigger the current `this.totalLength > dataLength` warning as totalLength is fixed.
        const publicKeyHex = 'EF'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        const longDataLength = expectedLength + 5; 

        keyboxData.set(publicKeyData, 0); // Only set the actual key part
        const x25519Parts = new X25519PublicKeyParts(keyboxData, 0, longDataLength);
        
        expect(x25519Parts.publicKey).toEqual(publicKeyData);
        expect(x25519Parts.totalLength).toBe(expectedLength);
    });
    
    it('should handle public key data at an offset', () => {
        const publicKeyHex = '1A'.repeat(expectedLength);
        const publicKeyData = hexToUint8Array(publicKeyHex);
        const offset = 10;

        keyboxData.set(publicKeyData, offset);
        const x25519Parts = new X25519PublicKeyParts(keyboxData, offset, publicKeyData.length);

        expect(x25519Parts.publicKey).toEqual(publicKeyData);
        expect(x25519Parts.totalLength).toBe(expectedLength);
    });
});
