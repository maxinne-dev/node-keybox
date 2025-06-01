
import { describe, it, expect, vi } from 'vitest';
import { SEIPDData } from '../../../models/packets/SEIPDData.js';
import { SEIPD_VERSION_1, SEIPD_VERSION_2, AEAD_AUTH_TAG_LENGTH, SymmetricKeyAlgorithm, AEADAlgorithm } from '../../../constants.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';
import { ISEIPDDataV1, ISEIPDDataV2 } from '../../../types.js';

// Define expected JSON data shapes for clarity in tests
type SEIPD_V1_JSON_Data = {
    encryptedDataAndMDC_length: number;
    encryptedDataAndMDC_hex_preview: string;
};

type SEIPD_V2_JSON_Data = {
    cipherAlgorithm: string;
    cipherAlgorithmId: SymmetricKeyAlgorithm;
    aeadAlgorithm: string;
    aeadAlgorithmId: AEADAlgorithm;
    chunkSizeOctet: number;
    chunkSizeActual: number;
    salt_hex: string;
    encryptedDataWithChunkTags_length: number;
    finalAuthenticationTag_hex: string;
};


describe('SEIPDData', () => {
    const keyboxData = new Uint8Array(256); // Dummy buffer

    describe('Version 1', () => {
        it('should parse SEIPD v1 data correctly', () => {
            const encryptedDataAndMDCHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"; // 32 bytes
            const packetDataHex = SEIPD_VERSION_1.toString(16).padStart(2, '0') + encryptedDataAndMDCHex;
            const packetDataBytes = hexToUint8Array(packetDataHex);

            keyboxData.set(packetDataBytes, 0);
            const seipd = new SEIPDData(keyboxData, 0, packetDataBytes.length);

            expect(seipd.version).toBe(SEIPD_VERSION_1);
            if (seipd.version === SEIPD_VERSION_1) {
                expect((seipd.data as ISEIPDDataV1).encryptedDataAndMDC).toEqual(hexToUint8Array(encryptedDataAndMDCHex));
            } else {
                expect.fail('Version mismatch');
            }
        });

        it('should produce correct JSON for v1', () => {
            const dataHex = "AA".repeat(40);
            const packetDataBytes = hexToUint8Array(SEIPD_VERSION_1.toString(16).padStart(2,'0') + dataHex);
            keyboxData.set(packetDataBytes, 0);
            const seipd = new SEIPDData(keyboxData, 0, packetDataBytes.length);
            const json = seipd.toJSON();

            expect(json.version).toBe(SEIPD_VERSION_1);
            if (json.version === SEIPD_VERSION_1) {
                const jsonData = json.data as SEIPD_V1_JSON_Data;
                expect(jsonData.encryptedDataAndMDC_length).toBe(40);
                expect(jsonData.encryptedDataAndMDC_hex_preview).toBe(dataHex.substring(0,64).toLowerCase() + "...");
            } else {
                expect.fail("JSON version mismatch for V1 test");
            }
        });
    });

    describe('Version 2', () => {
        const cipherAlgo = SymmetricKeyAlgorithm.AES128; // 7
        const aeadAlgo = AEADAlgorithm.OCB; // 2
        const chunkSizeOctet = 6; // 2^(6+6) = 2^12 = 4096 bytes
        const saltHex = "00".repeat(32);
        const encryptedDataHex = "11".repeat(50); // some encrypted data
        const finalAuthTagHex = "FF".repeat(AEAD_AUTH_TAG_LENGTH);

        const v2HeaderHex = 
            SEIPD_VERSION_2.toString(16).padStart(2, '0') +
            cipherAlgo.toString(16).padStart(2, '0') +
            aeadAlgo.toString(16).padStart(2, '0') +
            chunkSizeOctet.toString(16).padStart(2, '0') +
            saltHex;
        const validV2DataHex = v2HeaderHex + encryptedDataHex + finalAuthTagHex;
        const validV2DataBytes = hexToUint8Array(validV2DataHex);


        it('should parse SEIPD v2 data correctly', () => {
            keyboxData.set(validV2DataBytes, 0);
            const seipd = new SEIPDData(keyboxData, 0, validV2DataBytes.length);

            expect(seipd.version).toBe(SEIPD_VERSION_2);
            if (seipd.version === SEIPD_VERSION_2) {
                const v2data = seipd.data as ISEIPDDataV2;
                expect(v2data.cipherAlgorithm).toBe(cipherAlgo);
                expect(v2data.aeadAlgorithm).toBe(aeadAlgo);
                expect(v2data.chunkSizeOctet).toBe(chunkSizeOctet);
                expect(v2data.salt).toEqual(hexToUint8Array(saltHex));
                expect(v2data.encryptedDataWithChunkTags).toEqual(hexToUint8Array(encryptedDataHex));
                expect(v2data.finalAuthenticationTag).toEqual(hexToUint8Array(finalAuthTagHex));
            } else {
                expect.fail('Version mismatch');
            }
        });
        
        it('should throw if v2 data length is too short for minimal fields', () => {
            const minV2RequiredDataLength = 1+1+1+32+AEAD_AUTH_TAG_LENGTH; // 51 bytes for content
            const shortDataHex = SEIPD_VERSION_2.toString(16).padStart(2,'0') + "070206" + "00".repeat(32); // content = 36 bytes
            const shortDataBytes = hexToUint8Array(shortDataHex); // total packet data = 1 (version) + 36 = 37 bytes
            keyboxData.set(shortDataBytes, 0);
            // Data portion length will be 36. Minimal is 51.
            expect(() => new SEIPDData(keyboxData, 0, shortDataBytes.length))
                .toThrow(`SEIPDData v2: Data portion length ${35} too short for minimal fields and tag (needs at least ${minV2RequiredDataLength}).`);
        });

        it('should throw if v2 data length is too short for encrypted data and tag', () => {
            const minV2RequiredDataLength = 1+1+1+32+AEAD_AUTH_TAG_LENGTH; // 51 bytes for content
            const dataTooShortForTagHex = v2HeaderHex + "11".repeat(5); // content = 36 (header part) + 5 (data) = 41 bytes
            const dataTooShortForTagBytes = hexToUint8Array(dataTooShortForTagHex); // total packet data = 1 (version) + 41 = 42 bytes
             keyboxData.set(dataTooShortForTagBytes,0);
             // Data portion length will be 41. Minimal is 51.
             expect(() => new SEIPDData(keyboxData, 0, dataTooShortForTagBytes.length))
                .toThrow(`SEIPDData v2: Data portion length ${40} too short for minimal fields and tag (needs at least ${minV2RequiredDataLength}).`);
        });


        it('should produce correct JSON for v2', () => {
            keyboxData.set(validV2DataBytes, 0);
            const seipd = new SEIPDData(keyboxData, 0, validV2DataBytes.length);
            const json = seipd.toJSON();
            
            expect(json.version).toBe(SEIPD_VERSION_2);
            if (json.version === SEIPD_VERSION_2) {
                const jsonData = json.data as SEIPD_V2_JSON_Data; 
                expect(jsonData.cipherAlgorithm).toBe('AES128');
                expect(jsonData.aeadAlgorithm).toBe('OCB');
                expect(jsonData.chunkSizeOctet).toBe(chunkSizeOctet);
                expect(jsonData.chunkSizeActual).toBe(1 << (chunkSizeOctet + 6));
                expect(jsonData.salt_hex).toBe(saltHex);
                expect(jsonData.encryptedDataWithChunkTags_length).toBe(hexToUint8Array(encryptedDataHex).length);
                expect(jsonData.finalAuthenticationTag_hex).toBe(finalAuthTagHex.toLowerCase());
            } else {
                expect.fail("JSON version mismatch for V2 test");
            }
        });

    });

    it('should throw for unsupported version', () => {
        const packetDataBytes = hexToUint8Array("03" + "00".repeat(10)); // Version 3
        keyboxData.set(packetDataBytes, 0);
        expect(() => new SEIPDData(keyboxData, 0, packetDataBytes.length))
            .toThrow('SEIPDData: Unsupported version 3.');
    });
    
    it('should throw if data length too short for version byte', () => {
        expect(() => new SEIPDData(keyboxData, 0, 0))
            .toThrow('SEIPDData: Data length too short for version.');
    });
});
