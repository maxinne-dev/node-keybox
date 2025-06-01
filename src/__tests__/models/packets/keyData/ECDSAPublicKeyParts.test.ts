
import { describe, it, expect, vi } from 'vitest';
import { ECDSAPublicKeyParts } from '../../../../models/packets/keyData/ECDSAPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';

describe('ECDSAPublicKeyParts', () => {
    const keyboxData = new Uint8Array(256); // Dummy buffer

    // RFC 9580 Section 5.5.5.4 & 9.2
    // OID for NIST P-256: 8 octets data (2A8648CE3D030107)
    // Point: SEC1 format (0x04 || x || y), x and y are 32 bytes for P-256
    const p256OidDataHex = '2A8648CE3D030107';
    const oidFieldHex = '08' + p256OidDataHex; // Length 8, then 8 bytes OID

    const pointXHex = '01'.repeat(32);
    const pointYHex = '02'.repeat(32);
    const pointValueHex = '04' + pointXHex + pointYHex; // SEC1 uncompressed form (1 + 32 + 32 = 65 bytes)
    // Bit length of pointValueHex (65 bytes = 520 bits) is 0x0208
    const pointMpiHex = '0208' + pointValueHex;

    const validDataHex = oidFieldHex + pointMpiHex;
    const validData = hexToUint8Array(validDataHex);
    const expectedOidLength = 1 + 8; // OID length octet + OID data
    const expectedPointMpiLength = 2 + 65; // Point MPI length octets + point data
    const expectedTotalLength = expectedOidLength + expectedPointMpiLength; // 9 + 67 = 76

    it('should parse valid ECDSA public key parts correctly', () => {
        keyboxData.set(validData, 0);
        const ecdsaParts = new ECDSAPublicKeyParts(keyboxData, 0, validData.length);

        expect(ecdsaParts.oid).toEqual(hexToUint8Array(p256OidDataHex));
        expect(ecdsaParts.point).toEqual(hexToUint8Array(pointValueHex)); // Stores mpiValueBytes
        expect(ecdsaParts.totalLength).toBe(expectedTotalLength);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validData, 0);
        const ecdsaParts = new ECDSAPublicKeyParts(keyboxData, 0, validData.length);
        const json = ecdsaParts.toJSON();

        expect(json.oid_hex).toBe(p256OidDataHex.toLowerCase());
        expect(json.point_mpi_hex).toBe(pointValueHex.toLowerCase());
        expect(json.totalLength).toBe(expectedTotalLength);
    });

    it('should warn if parsed data length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxData.set(validData, 0);
        
        const shortDataLength = expectedTotalLength - 5;
        new ECDSAPublicKeyParts(keyboxData, 0, shortDataLength);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`ECDSAPublicKeyParts: Parsed data length (${expectedTotalLength}) exceeds provided data length (${shortDataLength}).`);
        consoleWarnSpy.mockRestore();
    });
});
