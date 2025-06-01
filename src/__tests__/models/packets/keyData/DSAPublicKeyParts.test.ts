
import { describe, it, expect, vi } from 'vitest';
import { DSAPublicKeyParts } from '../../../../models/packets/keyData/DSAPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('DSAPublicKeyParts', () => {
    const keyboxData = new Uint8Array(1024); // Dummy buffer for tests

    // RFC 9580 Section 5.5.5.2
    // MPI p, MPI q, MPI g, MPI y
    const pValHex = '01'.repeat(128); // 1024-bit p
    const qValHex = '02'.repeat(20);  // 160-bit q
    const gValHex = '03'.repeat(128); // 1024-bit g
    const yValHex = '04'.repeat(128); // 1024-bit y

    const pMpiHex = '0400' + pValHex; // 1024 bits
    const qMpiHex = '00a0' + qValHex; // 160 bits
    const gMpiHex = '0400' + gValHex; // 1024 bits
    const yMpiHex = '0400' + yValHex; // 1024 bits
    const validMpiDataHex = pMpiHex + qMpiHex + gMpiHex + yMpiHex;
    const validMpiData = hexToUint8Array(validMpiDataHex);
    const expectedTotalLength = (2 + 128) + (2 + 20) + (2 + 128) + (2 + 128); // 412

    it('should parse valid DSA public key MPIs correctly', () => {
        keyboxData.set(validMpiData, 0);
        const dsaParts = new DSAPublicKeyParts(keyboxData, 0, validMpiData.length);

        expect(dsaParts.primeP).toEqual(hexToUint8Array(pValHex));
        expect(dsaParts.groupOrderQ).toEqual(hexToUint8Array(qValHex));
        expect(dsaParts.groupGeneratorG).toEqual(hexToUint8Array(gValHex));
        expect(dsaParts.publicKeyY).toEqual(hexToUint8Array(yValHex));
        expect(dsaParts.totalLength).toBe(expectedTotalLength);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validMpiData, 0);
        const dsaParts = new DSAPublicKeyParts(keyboxData, 0, validMpiData.length);
        const json = dsaParts.toJSON();

        expect(json.primeP_hex).toBe(pValHex.toLowerCase());
        expect(json.groupOrderQ_hex).toBe(qValHex.toLowerCase());
        expect(json.groupGeneratorG_hex).toBe(gValHex.toLowerCase());
        expect(json.publicKeyY_hex).toBe(yValHex.toLowerCase());
        expect(json.totalLength).toBe(expectedTotalLength);
    });

    it('should warn if parsed MPIs length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxData.set(validMpiData, 0);
        
        const shortDataLength = expectedTotalLength - 10;
        new DSAPublicKeyParts(keyboxData, 0, shortDataLength);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`DSAPublicKeyParts: Parsed MPIs length (${expectedTotalLength}) exceeds provided data length (${shortDataLength}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle MPIs at an offset within keyboxData', () => {
        const offset = 50;
        keyboxData.set(validMpiData, offset);
        const dsaParts = new DSAPublicKeyParts(keyboxData, offset, validMpiData.length);

        expect(dsaParts.primeP).toEqual(hexToUint8Array(pValHex));
        expect(dsaParts.totalLength).toBe(expectedTotalLength);
    });
});
