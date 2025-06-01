
import { describe, it, expect, vi } from 'vitest';
import { RSASignatureParts } from '../../../../models/packets/signatureData/RSASignatureParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('RSASignatureParts', () => {
    const keyboxData = new Uint8Array(2048); // Dummy larger buffer for tests

    it('should parse a valid RSA signature MPI correctly', () => {
        // Example: MPI for a signature value. Bit length 2048 (0x0800 bits = 256 bytes)
        // Length: 0x0800
        // Value: 256 bytes of some signature data (e.g., all 0xAA)
        const signatureValueHex = 'AA'.repeat(256);
        const mpiDataHex = '0800' + signatureValueHex;
        const mpiData = hexToUint8Array(mpiDataHex);
        
        keyboxData.set(mpiData, 0);
        const rsaSigParts = new RSASignatureParts(keyboxData, 0, mpiData.length);

        expect(rsaSigParts.signatureMPI).toEqual(hexToUint8Array(signatureValueHex));
        expect(rsaSigParts.totalLength).toBe(2 + 256); // 2 for length, 256 for value
    });

    it('should produce correct JSON output', () => {
        const signatureValueHex = 'BB'.repeat(128);
        const mpiDataHex = '0400' + signatureValueHex; // 1024 bits
        const mpiData = hexToUint8Array(mpiDataHex);
        
        keyboxData.set(mpiData, 0);
        const rsaSigParts = new RSASignatureParts(keyboxData, 0, mpiData.length);
        const json = rsaSigParts.toJSON();

        expect(json.signatureMPI_hex).toBe(signatureValueHex.toLowerCase());
        expect(json.totalLength).toBe(2 + 128);
    });

    it('should warn if parsed MPI length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        
        const signatureValueHex = 'CC'.repeat(64);
        const mpiDataHex = '0200' + signatureValueHex; // 512 bits = 64 bytes value
        const mpiData = hexToUint8Array(mpiDataHex);

        keyboxData.set(mpiData, 0);
        // Provide a dataLength shorter than what the MPI actually is
        new RSASignatureParts(keyboxData, 0, mpiData.length - 10); 
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`RSASignatureParts: Parsed MPI length (${2 + 64}) exceeds provided data length (${mpiData.length - 10}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle MPI at an offset within keyboxData', () => {
        const signatureValueHex = 'DD'.repeat(32);
        const mpiDataHex = '0100' + signatureValueHex; // 256 bits = 32 bytes value
        const mpiData = hexToUint8Array(mpiDataHex);
        const offset = 50;

        keyboxData.set(mpiData, offset);
        const rsaSigParts = new RSASignatureParts(keyboxData, offset, mpiData.length);
        
        expect(rsaSigParts.signatureMPI).toEqual(hexToUint8Array(signatureValueHex));
        expect(rsaSigParts.totalLength).toBe(2 + 32);
    });
});
