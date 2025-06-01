
import { describe, it, expect, vi } from 'vitest';
import { EdDSALegacyPublicKeyParts } from '../../../../models/packets/keyData/EdDSALegacyPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('EdDSALegacyPublicKeyParts', () => {
    const keyboxData = new Uint8Array(128); // Dummy buffer

    // RFC 9580 Section 5.5.5.5 & 9.2
    // Ed25519Legacy OID: 9 octets data (2B06010401DA470F01)
    // Point: MPI of EC point Q in prefixed native form (0x40 || native_point_32_bytes)
    const ed25519LegacyOidDataHex = '2B06010401DA470F01';
    const oidFieldHex = '09' + ed25519LegacyOidDataHex; // Length 9, then 9 bytes OID

    const nativePointHex = '01'.repeat(32);
    const prefixedNativePointHex = '40' + nativePointHex; // 1 + 32 = 33 bytes
    // Bit length of prefixedNativePointHex (33 bytes = 264 bits). Max bit is bit 7 of 0x40, so 256 + 7 = 263
    // Smallest number of octets is 33. Highest bit is bit 6 of 0x40. 256 + 6 = 262. Bit length should be 263.
    // MPI bitlength for 0x40... (33 bytes) is (8*32 + 7) = 263 (0x0107) for 0x40 as MSB.
    const pointMpiHex = '0107' + prefixedNativePointHex; // 0x0107 = 263 bits

    const validDataHex = oidFieldHex + pointMpiHex;
    const validData = hexToUint8Array(validDataHex);
    const expectedOidLength = 1 + 9; // OID length octet + OID data
    const expectedPointMpiLength = 2 + 33; // Point MPI length octets + point data
    const expectedTotalLength = expectedOidLength + expectedPointMpiLength; // 10 + 35 = 45

    it('should parse valid EdDSALegacy public key parts correctly', () => {
        keyboxData.set(validData, 0);
        const eddsaParts = new EdDSALegacyPublicKeyParts(keyboxData, 0, validData.length);

        expect(eddsaParts.oid).toEqual(hexToUint8Array(ed25519LegacyOidDataHex));
        expect(eddsaParts.point).toEqual(hexToUint8Array(prefixedNativePointHex)); // Stores mpiValueBytes
        expect(eddsaParts.totalLength).toBe(expectedTotalLength);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validData, 0);
        const eddsaParts = new EdDSALegacyPublicKeyParts(keyboxData, 0, validData.length);
        const json = eddsaParts.toJSON();

        expect(json.oid_hex).toBe(ed25519LegacyOidDataHex.toLowerCase());
        expect(json.point_mpi_hex).toBe(prefixedNativePointHex.toLowerCase());
        expect(json.totalLength).toBe(expectedTotalLength);
    });

    it('should warn if parsed data length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxData.set(validData, 0);
        
        const shortDataLength = expectedTotalLength - 5;
        new EdDSALegacyPublicKeyParts(keyboxData, 0, shortDataLength);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`EdDSALegacyPublicKeyParts: Parsed data length (${expectedTotalLength}) exceeds provided data length (${shortDataLength}).`);
        consoleWarnSpy.mockRestore();
    });
});
