
import { describe, it, expect, vi } from 'vitest';
import { EdDSALegacySignatureParts } from '../../../../models/packets/signatureData/EdDSALegacySignatureParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('EdDSALegacySignatureParts', () => {
    const keyboxData = new Uint8Array(512); // Dummy larger buffer

    // RFC 9580, Section 5.2.3.3.1 for Ed25519Legacy:
    // MPI of an EC point R, ... native (little-endian) octet string up to 32 octets.
    // MPI of EdDSA value S, ... native (little-endian) format with a length up to 32 octets.
    // Note: MPIs store big-endian. The "native" EdDSA values are little-endian.
    // The MPI parsing itself handles the big-endian reading from the wire.
    // The underlying data for r and s, if they were native EdDSA, would be little-endian, but
    // when stored as an MPI *value*, they are just byte strings.
    // For testing, we'll assume the MPI values are correctly formatted byte strings.

    it('should parse valid EdDSALegacy signature MPIs (r_mpi and s_mpi) correctly', () => {
        // Example r_mpi: 32 bytes, s_mpi: 32 bytes
        // MPI for r_mpi: 0x0100 (256 bits) + 32 bytes of data
        // MPI for s_mpi: 0x0100 (256 bits) + 32 bytes of data
        const rValueHex = '01'.repeat(32);
        const sValueHex = '02'.repeat(32);
        const rMpiHex = '0100' + rValueHex;
        const sMpiHex = '0100' + sValueHex;
        const mpiDataHex = rMpiHex + sMpiHex;
        const mpiData = hexToUint8Array(mpiDataHex);

        keyboxData.set(mpiData, 0);
        const eddsaSigParts = new EdDSALegacySignatureParts(keyboxData, 0, mpiData.length);

        expect(eddsaSigParts.r_mpi).toEqual(hexToUint8Array(rValueHex));
        expect(eddsaSigParts.s_mpi).toEqual(hexToUint8Array(sValueHex));
        expect(eddsaSigParts.totalLength).toBe((2 + 32) + (2 + 32)); // r_len + r_val + s_len + s_val
    });

    it('should produce correct JSON output', () => {
        const rValueHex = 'AA'.repeat(32);
        const sValueHex = 'BB'.repeat(32);
        const mpiData = hexToUint8Array('0100' + rValueHex + '0100' + sValueHex);

        keyboxData.set(mpiData, 0);
        const eddsaSigParts = new EdDSALegacySignatureParts(keyboxData, 0, mpiData.length);
        const json = eddsaSigParts.toJSON();

        expect(json.r_mpi_hex).toBe(rValueHex.toLowerCase());
        expect(json.s_mpi_hex).toBe(sValueHex.toLowerCase());
        expect(json.totalLength).toBe(68);
    });

    it('should warn if parsed MPIs length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        
        const rValueHex = 'CC'.repeat(32);
        const sValueHex = 'DD'.repeat(32);
        const mpiDataHex = '0100' + rValueHex + '0100' + sValueHex;
        const mpiData = hexToUint8Array(mpiDataHex);

        keyboxData.set(mpiData, 0);
        // Provide a dataLength shorter than what the MPIs actually are
        new EdDSALegacySignatureParts(keyboxData, 0, mpiData.length - 10);

        expect(consoleWarnSpy).toHaveBeenCalledWith(`EdDSALegacySignatureParts: Parsed MPIs length (${mpiData.length}) exceeds provided data length (${mpiData.length - 10}).`);
        consoleWarnSpy.mockRestore();
    });
});
