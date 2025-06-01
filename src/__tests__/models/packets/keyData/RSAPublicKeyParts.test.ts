
import { describe, it, expect, vi } from 'vitest';
import { RSAPublicKeyParts } from '../../../../models/packets/keyData/RSAPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('RSAPublicKeyParts', () => {
    const keyboxData = new Uint8Array(1024); // Dummy larger buffer for tests

    it('should parse valid RSA public key MPIs (n and e) correctly', () => {
        // Example n: 2048 bits (256 bytes), e: 17 bits (0x0011 -> 010001 = 3 bytes for MPI value if padded, or 0x11 if 0x0011 is the bitlength)
        // MPI for n: bit length 0x0800 (2048), value (256 bytes of 0xAA)
        // MPI for e: bit length 0x0011 (17), value (0x010001 -> actually 3 bytes if 17 bits, e.g. 0x01, 0x00, 0x01)
        // Let's use simpler e: bit length 0x0010 (16 bits), value 0xFFFF (2 bytes)
        const nValueHex = 'AA'.repeat(256);
        const eValueHex = 'FFFF';
        const nMpiDataHex = '0800' + nValueHex; // 2048 bits for n
        const eMpiDataHex = '0010' + eValueHex; // 16 bits for e
        const mpiDataHex = nMpiDataHex + eMpiDataHex;
        const mpiData = hexToUint8Array(mpiDataHex);
        
        keyboxData.set(mpiData, 0);
        const rsaParts = new RSAPublicKeyParts(keyboxData, 0, mpiData.length);

        expect(rsaParts.modulusN).toEqual(hexToUint8Array(nValueHex));
        expect(rsaParts.bitLengthModN).toBe(0x0800);
        expect(rsaParts.publicExponentE).toEqual(hexToUint8Array(eValueHex));
        expect(rsaParts.bitLengthExpE).toBe(0x0010);
        expect(rsaParts.totalLength).toBe((2 + 256) + (2 + 2)); // n_len_bytes + n_val_bytes + e_len_bytes + e_val_bytes
    });

    it('should produce correct JSON output', () => {
        const nValueHex = 'BB'.repeat(128); // 1024 bits
        const eValueHex = '010001'; // Standard e = 65537, 17 bits. MPI value 0x010001 (3 bytes)
        const nMpiDataHex = '0400' + nValueHex; // 1024 bits
        const eMpiDataHex = '0011' + eValueHex; // 17 bits, value 0x010001
        const mpiData = hexToUint8Array(nMpiDataHex + eMpiDataHex);
        
        keyboxData.set(mpiData, 0);
        const rsaParts = new RSAPublicKeyParts(keyboxData, 0, mpiData.length);
        const json = rsaParts.toJSON();

        expect(json.modulusN_hex).toBe(nValueHex.toLowerCase());
        expect(json.publicExponentE_hex).toBe(eValueHex.toLowerCase());
        expect(json.bitLengthModN).toBe(1024);
        expect(json.bitLengthExpE).toBe(17);
        expect(json.totalLength).toBe((2 + 128) + (2 + 3));
    });

    it('should warn if parsed MPIs length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        
        const nValueHex = 'CC'.repeat(64); // 512 bits
        const eValueHex = '03'; // 2 bits, MPI len 0x0002, value 0x03 (1 byte)
        const nMpiDataHex = '0200' + nValueHex;
        const eMpiDataHex = '0002' + eValueHex;
        const mpiDataHex = nMpiDataHex + eMpiDataHex;
        const mpiData = hexToUint8Array(mpiDataHex);
        const actualTotalLength = (2 + 64) + (2 + 1); // 69

        keyboxData.set(mpiData, 0);
        // Provide a dataLength shorter than what the MPIs actually are
        new RSAPublicKeyParts(keyboxData, 0, actualTotalLength - 5); 
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`RSAPublicKeyParts: Parsed MPIs length (${actualTotalLength}) exceeds provided data length (${actualTotalLength - 5}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle MPIs at an offset within keyboxData', () => {
        const nValueHex = 'DD'.repeat(32); // 256 bits
        const eValueHex = '0101'; // 9 bits, MPI len 0x0009, value 0x0101 (2 bytes)
        const nMpiDataHex = '0100' + nValueHex;
        const eMpiDataHex = '0009' + eValueHex;
        const mpiDataHex = nMpiDataHex + eMpiDataHex;
        const mpiData = hexToUint8Array(mpiDataHex);
        const offset = 50;

        keyboxData.set(mpiData, offset);
        const rsaParts = new RSAPublicKeyParts(keyboxData, offset, mpiData.length);
        
        expect(rsaParts.modulusN).toEqual(hexToUint8Array(nValueHex));
        expect(rsaParts.publicExponentE).toEqual(hexToUint8Array(eValueHex));
        expect(rsaParts.totalLength).toBe((2 + 32) + (2 + 2));
    });
});
