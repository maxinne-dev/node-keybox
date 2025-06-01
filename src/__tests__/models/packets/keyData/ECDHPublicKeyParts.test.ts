
import { describe, it, expect, vi } from 'vitest';
import { ECDHPublicKeyParts } from '../../../../models/packets/keyData/ECDHPublicKeyParts.js';
import { hexToUint8Array } from '../../../test-utils.js';
import { Buffer } from 'buffer';
import { HashAlgorithm, SymmetricKeyAlgorithm } from '../../../../constants.js';

describe('ECDHPublicKeyParts', () => {
    const keyboxDataForGeneralTests = new Uint8Array(256); // Dummy buffer for most tests

    // RFC 9580 Section 5.5.5.6
    // OID for NIST P-256: 8 octets data
    const p256OidDataHex = '2A8648CE3D030107';
    const oidFieldHex = '08' + p256OidDataHex; // Length 8, then 8 bytes OID

    // Point: SEC1 format (0x04 || x || y), x and y are 32 bytes for P-256
    const pointXHex = '01'.repeat(32);
    const pointYHex = '02'.repeat(32);
    const pointValueHex = '04' + pointXHex + pointYHex; // 65 bytes
    const pointMpiHex = '0208' + pointValueHex; // 0x0208 = 520 bits

    // KDF parameters: size (1) + reserved (1) + hash_id (1) + sym_algo_id (1)
    // Example: size 0x03, reserved 0x01, hash SHA256 (8), sym algo AES128 (7)
    const kdfParamsHex = '03010807'; 

    const validDataHex = oidFieldHex + pointMpiHex + kdfParamsHex;
    const validData = hexToUint8Array(validDataHex);
    const expectedOidLength = 1 + 8;
    const expectedPointMpiLength = 2 + 65;
    const expectedKdfLength = 1 + 3; // size_octet + 3 params
    const expectedTotalLength = expectedOidLength + expectedPointMpiLength + expectedKdfLength; // 9 + 67 + 4 = 80

    it('should parse valid ECDH public key parts correctly', () => {
        keyboxDataForGeneralTests.set(validData, 0);
        const ecdhParts = new ECDHPublicKeyParts(keyboxDataForGeneralTests, 0, validData.length);

        expect(ecdhParts.oid).toEqual(hexToUint8Array(p256OidDataHex));
        expect(ecdhParts.point).toEqual(hexToUint8Array(pointValueHex));
        expect(ecdhParts.kdfParameters.hashAlgorithmId).toBe(HashAlgorithm.SHA256); // 8
        expect(ecdhParts.kdfParameters.symmetricAlgorithmId).toBe(SymmetricKeyAlgorithm.AES128); // 7
        expect(ecdhParts.totalLength).toBe(expectedTotalLength);
    });

    it('should produce correct JSON output', () => {
        keyboxDataForGeneralTests.set(validData, 0);
        const ecdhParts = new ECDHPublicKeyParts(keyboxDataForGeneralTests, 0, validData.length);
        const json = ecdhParts.toJSON();

        expect(json.oid_hex).toBe(p256OidDataHex.toLowerCase());
        expect(json.point_mpi_hex).toBe(pointValueHex.toLowerCase());
        expect(json.kdfParameters.hashAlgorithmId).toBe(HashAlgorithm.SHA256);
        expect(json.kdfParameters.symmetricAlgorithmId).toBe(SymmetricKeyAlgorithm.AES128);
        expect(json.totalLength).toBe(expectedTotalLength);
    });

    it('should warn if parsed data length exceeds provided data length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxDataForGeneralTests.set(validData, 0);
        
        const shortDataLength = expectedTotalLength - 5;
        new ECDHPublicKeyParts(keyboxDataForGeneralTests, 0, shortDataLength);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`ECDHPublicKeyParts: Parsed data length (${expectedTotalLength}) exceeds provided data length (${shortDataLength}).`);
        consoleWarnSpy.mockRestore();
    });

    it('should correctly parse KDF with non-standard size if data allows, but throw if assumed read goes out of bounds', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        
        // KDF: size 0x02, content 0x0108 (reserved=0x01, hashId=0x08). Symm algo ID is missing from this data.
        const malformedKdfParamsHex = '020108'; 
        const dataForECDHMalformedKDFHex = oidFieldHex + pointMpiHex + malformedKdfParamsHex;
        const keyboxDataForThisTest = hexToUint8Array(dataForECDHMalformedKDFHex); // Use precisely sized buffer
        
        // parseKdfParameters will warn about kdfParamsSize=2.
        // It will then attempt to read 3 parameters (reserved, hash, symm).
        // The read for symmetricAlgorithmId (the 3rd parameter) should go out of bounds 
        // of keyboxDataForThisTest because malformedKdfParamsHex only provides 2 parameter bytes.
        // Buffer.readUInt8 out of bounds throws RangeError.
        expect(() => new ECDHPublicKeyParts(keyboxDataForThisTest, 0, keyboxDataForThisTest.length)).toThrow(
            RangeError 
        );
        
        // Check that the warning about kdfParamsSize was still issued by parseKdfParameters
        expect(consoleWarnSpy).toHaveBeenCalledWith('parseKdfParameters: Expected KDF parameters size 3, got 2. Parsing will proceed assuming 3.');
        consoleWarnSpy.mockRestore();
    });
});
