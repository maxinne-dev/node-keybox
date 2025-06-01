
import { describe, it, expect, vi } from 'vitest';
import { ElgamalPublicKeyParts } from '../../../../models/packets/keyData/ElgamalPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('ElgamalPublicKeyParts', () => {
    const keyboxData = new Uint8Array(1024); // Dummy buffer for tests

    // RFC 9580 Section 5.5.5.3
    // MPI p, MPI g, MPI y
    const pValHex = '01'.repeat(128); // 1024-bit p
    const gValHex = '02'.repeat(128); // 1024-bit g
    const yValHex = '03'.repeat(128); // 1024-bit y

    const pMpiHex = '0400' + pValHex; // 1024 bits
    const gMpiHex = '0400' + gValHex; // 1024 bits
    const yMpiHex = '0400' + yValHex; // 1024 bits
    const validMpiDataHex = pMpiHex + gMpiHex + yMpiHex;
    const validMpiData = hexToUint8Array(validMpiDataHex);
    const expectedTotalLength = (2 + 128) + (2 + 128) + (2 + 128); // 390

    it('should parse valid Elgamal public key MPIs correctly', () => {
        keyboxData.set(validMpiData, 0);
        const elgamalParts = new ElgamalPublicKeyParts(keyboxData, 0, validMpiData.length);

        expect(elgamalParts.primeP).toEqual(hexToUint8Array(pValHex));
        expect(elgamalParts.groupGeneratorG).toEqual(hexToUint8Array(gValHex));
        expect(elgamalParts.publicKeyY).toEqual(hexToUint8Array(yValHex));
        expect(elgamalParts.totalLength).toBe(expectedTotalLength);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validMpiData, 0);
        const elgamalParts = new ElgamalPublicKeyParts(keyboxData, 0, validMpiData.length);
        const json = elgamalParts.toJSON();

        expect(json.primeP_hex).toBe(pValHex.toLowerCase());
        expect(json.groupGeneratorG_hex).toBe(gValHex.toLowerCase());
        expect(json.publicKeyY_hex).toBe(yValHex.toLowerCase());
        expect(json.totalLength).toBe(expectedTotalLength);
    });

    it('should warn if parsed MPIs length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxData.set(validMpiData, 0);
        
        const shortDataLength = expectedTotalLength - 10;
        new ElgamalPublicKeyParts(keyboxData, 0, shortDataLength);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`ElgamalPublicKeyParts: Parsed MPIs length (${expectedTotalLength}) exceeds provided data length (${shortDataLength}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle MPIs at an offset within keyboxData', () => {
        const offset = 50;
        keyboxData.set(validMpiData, offset);
        const elgamalParts = new ElgamalPublicKeyParts(keyboxData, offset, validMpiData.length);

        expect(elgamalParts.primeP).toEqual(hexToUint8Array(pValHex));
        expect(elgamalParts.totalLength).toBe(expectedTotalLength);
    });
});
