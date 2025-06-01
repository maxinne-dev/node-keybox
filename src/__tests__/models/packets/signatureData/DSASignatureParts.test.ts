
import { describe, it, expect, vi } from 'vitest';
import { DSASignatureParts } from '../../../../models/packets/signatureData/DSASignatureParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('DSASignatureParts', () => {
    const keyboxData = new Uint8Array(512); // Dummy larger buffer

    it('should parse valid DSA signature MPIs (r and s) correctly', () => {
        // Example r: 20 bytes, s: 20 bytes
        // MPI for r: 0x00a0 (160 bits) + 20 bytes of data
        // MPI for s: 0x00a0 (160 bits) + 20 bytes of data
        const rValueHex = '01'.repeat(20);
        const sValueHex = '02'.repeat(20);
        const rMpiHex = '00a0' + rValueHex;
        const sMpiHex = '00a0' + sValueHex;
        const mpiDataHex = rMpiHex + sMpiHex;
        const mpiData = hexToUint8Array(mpiDataHex);

        keyboxData.set(mpiData, 0);
        const dsaSigParts = new DSASignatureParts(keyboxData, 0, mpiData.length);

        expect(dsaSigParts.r).toEqual(hexToUint8Array(rValueHex));
        expect(dsaSigParts.s).toEqual(hexToUint8Array(sValueHex));
        expect(dsaSigParts.totalLength).toBe((2 + 20) + (2 + 20)); // r_len + r_val + s_len + s_val
    });

    it('should produce correct JSON output', () => {
        const rValueHex = 'AA'.repeat(20);
        const sValueHex = 'BB'.repeat(20);
        const mpiData = hexToUint8Array('00a0' + rValueHex + '00a0' + sValueHex);

        keyboxData.set(mpiData, 0);
        const dsaSigParts = new DSASignatureParts(keyboxData, 0, mpiData.length);
        const json = dsaSigParts.toJSON();

        expect(json.r_hex).toBe(rValueHex.toLowerCase());
        expect(json.s_hex).toBe(sValueHex.toLowerCase());
        expect(json.totalLength).toBe(44);
    });

    it('should warn if parsed MPIs length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        
        const rValueHex = 'CC'.repeat(20);
        const sValueHex = 'DD'.repeat(20);
        const mpiDataHex = '00a0' + rValueHex + '00a0' + sValueHex;
        const mpiData = hexToUint8Array(mpiDataHex);

        keyboxData.set(mpiData, 0);
        // Provide a dataLength shorter than what the MPIs actually are
        new DSASignatureParts(keyboxData, 0, mpiData.length - 5);

        expect(consoleWarnSpy).toHaveBeenCalledWith(`DSASignatureParts: Parsed MPIs length (${mpiData.length}) exceeds provided data length (${mpiData.length - 5}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle MPIs at an offset within keyboxData', () => {
        const rValueHex = 'EE'.repeat(16);
        const sValueHex = 'FF'.repeat(16);
        const mpiDataHex = '0080' + rValueHex + '0080' + sValueHex; // 128-bit r and s
        const mpiData = hexToUint8Array(mpiDataHex);
        const offset = 30;

        keyboxData.set(mpiData, offset);
        const dsaSigParts = new DSASignatureParts(keyboxData, offset, mpiData.length);

        expect(dsaSigParts.r).toEqual(hexToUint8Array(rValueHex));
        expect(dsaSigParts.s).toEqual(hexToUint8Array(sValueHex));
        expect(dsaSigParts.totalLength).toBe((2 + 16) + (2 + 16));
    });
});
