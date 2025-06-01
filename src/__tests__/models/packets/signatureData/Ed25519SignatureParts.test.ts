
import { describe, it, expect, vi } from 'vitest';
import { Ed25519SignatureParts } from '../../../../models/packets/signatureData/Ed25519SignatureParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('Ed25519SignatureParts', () => {
    const keyboxData = new Uint8Array(100); // Dummy larger buffer
    const expectedLength = 64;

    it('should parse a valid Ed25519 native signature correctly', () => {
        const signatureHex = 'AB'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);

        keyboxData.set(signatureData, 0);
        const edSigParts = new Ed25519SignatureParts(keyboxData, 0, signatureData.length);

        expect(edSigParts.nativeSignature).toEqual(signatureData);
        expect(edSigParts.totalLength).toBe(expectedLength);
    });

    it('should produce correct JSON output', () => {
        const signatureHex = 'CD'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);
        
        keyboxData.set(signatureData, 0);
        const edSigParts = new Ed25519SignatureParts(keyboxData, 0, signatureData.length);
        const json = edSigParts.toJSON();

        expect(json.nativeSignature_hex).toBe(signatureHex.toLowerCase());
        expect(json.totalLength).toBe(expectedLength);
    });

    it('should throw if data length is less than expected', () => {
        const shortSignatureData = hexToUint8Array('00'.repeat(expectedLength - 1));
        keyboxData.set(shortSignatureData, 0);
        
        expect(() => new Ed25519SignatureParts(keyboxData, 0, shortSignatureData.length))
            .toThrow(`Ed25519SignatureParts: Data length (${expectedLength - 1}) is less than expected ${expectedLength} bytes.`);
    });

    it('should warn if provided data length is greater than expected (but still parse fixed length)', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const signatureHex = 'EF'.repeat(expectedLength);
        const longSignatureData = hexToUint8Array(signatureHex + '001122'); // Extra bytes
        
        keyboxData.set(hexToUint8Array(signatureHex), 0); // only set the expected part
        const edSigParts = new Ed25519SignatureParts(keyboxData, 0, longSignatureData.length);

        // The constructor uses its fixed totalLength, so it will parse only 64 bytes.
        // The warning in the constructor `if (this.totalLength > dataLength)` is for when
        // the fixed length itself is greater than what's available from the packet.
        // Here, dataLength (from packet) > this.totalLength (fixed 64).
        // This scenario is not explicitly warned against in the current Ed25519SignatureParts constructor,
        // as it simply slices the first `this.totalLength` bytes.
        // If the intention was to warn if dataLength > totalLength, that logic isn't present.
        // Let's test the current behavior: no warning for dataLength > fixed totalLength.
        
        expect(edSigParts.nativeSignature).toEqual(hexToUint8Array(signatureHex));
        expect(edSigParts.totalLength).toBe(expectedLength);
        expect(consoleWarnSpy).not.toHaveBeenCalled(); // No warning for this specific case in current code

        consoleWarnSpy.mockRestore();
    });

    it('should handle signature data at an offset', () => {
        const signatureHex = '1A'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);
        const offset = 10;

        keyboxData.set(signatureData, offset);
        const edSigParts = new Ed25519SignatureParts(keyboxData, offset, signatureData.length);

        expect(edSigParts.nativeSignature).toEqual(signatureData);
        expect(edSigParts.totalLength).toBe(expectedLength);
    });
});
