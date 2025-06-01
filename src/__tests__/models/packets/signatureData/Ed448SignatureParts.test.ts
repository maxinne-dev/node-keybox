
import { describe, it, expect, vi } from 'vitest';
import { Ed448SignatureParts } from '../../../../models/packets/signatureData/Ed448SignatureParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('Ed448SignatureParts', () => {
    const keyboxData = new Uint8Array(150); // Dummy larger buffer
    const expectedLength = 114;

    it('should parse a valid Ed448 native signature correctly', () => {
        const signatureHex = 'AB'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);

        keyboxData.set(signatureData, 0);
        const edSigParts = new Ed448SignatureParts(keyboxData, 0, signatureData.length);

        expect(edSigParts.nativeSignature).toEqual(signatureData);
        expect(edSigParts.totalLength).toBe(expectedLength);
    });

    it('should produce correct JSON output', () => {
        const signatureHex = 'CD'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);
        
        keyboxData.set(signatureData, 0);
        const edSigParts = new Ed448SignatureParts(keyboxData, 0, signatureData.length);
        const json = edSigParts.toJSON();

        expect(json.nativeSignature_hex).toBe(signatureHex.toLowerCase());
        expect(json.totalLength).toBe(expectedLength);
    });

    it('should throw if data length is less than expected', () => {
        const shortSignatureData = hexToUint8Array('00'.repeat(expectedLength - 1));
        keyboxData.set(shortSignatureData, 0);
        
        expect(() => new Ed448SignatureParts(keyboxData, 0, shortSignatureData.length))
            .toThrow(`Ed448SignatureParts: Data length (${expectedLength - 1}) is less than expected ${expectedLength} bytes.`);
    });

    it('should handle signature data at an offset', () => {
        const signatureHex = '1A'.repeat(expectedLength);
        const signatureData = hexToUint8Array(signatureHex);
        const offset = 5;

        keyboxData.set(signatureData, offset);
        const edSigParts = new Ed448SignatureParts(keyboxData, offset, signatureData.length);

        expect(edSigParts.nativeSignature).toEqual(signatureData);
        expect(edSigParts.totalLength).toBe(expectedLength);
    });
});
