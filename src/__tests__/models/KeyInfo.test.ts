

import { describe, it, expect } from 'vitest';
import { KeyInfo } from '../../models/KeyInfo.js';
import { KEY_INFO_V1_FINGERPRINT_SIZE, KEY_INFO_V2_FINGERPRINT_SIZE, KEY_INFO_V2_KEYGRIP_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';
import type { IKeyInfo } from '../../types.js';

describe('KeyInfo', () => {
    const keyboxData = new Uint8Array(200); // Dummy larger buffer

    describe('Version 1 Blob', () => {
        // V1 KeyInfo: 20(fp) + 4(offsetKeyID) + 2(flags) + 2(RFU) = 28 bytes. keyInfoStructSize = 28.
        const v1KeyInfoData = hexToUint8Array(
            '0102030405060708090a0b0c0d0e0f1011121314' + // fingerprintV1 (20 bytes)
            '00000123' + // offsetKeyID (291)
            '0001' +     // keyFlags (qualifiedSignature = true)
            '0000'       // RFU
        );
        const v1StructSize = 28;

        it('should parse V1 KeyInfo correctly', () => {
            keyboxData.set(v1KeyInfoData, 0);
            const keyInfo = new KeyInfo(keyboxData, 0, v1StructSize, 1);

            expect(keyInfo.actualSizeInBlob).toBe(v1StructSize);
            expect(keyInfo.fingerprintV1).toEqual(hexToUint8Array('0102030405060708090a0b0c0d0e0f1011121314'));
            expect(keyInfo.offsetKeyID).toBe(291);
            expect(keyInfo.keyFlagsRaw).toEqual(hexToUint8Array('0001'));
            expect(keyInfo.keyFlagsParsed.qualifiedSignature).toBe(true);
            expect(keyInfo.keyFlagsParsed.is32ByteFingerprintInUse).toBeUndefined();
            expect(keyInfo.fingerprintV2).toBeUndefined();
            expect(keyInfo.keygrip).toBeUndefined();
        });

        it('should produce correct JSON for V1', () => {
            keyboxData.set(v1KeyInfoData, 0);
            const keyInfo = new KeyInfo(keyboxData, 0, v1StructSize, 1);
            const json = keyInfo.toJSON();
            
            expect(json.blobVersion).toBe(1); // Explicitly check the discriminant
            if (json.blobVersion === 1) {
                expect(json.fingerprintV1).toBe('0102030405060708090a0b0c0d0e0f1011121314');
                expect(json.offsetKeyID).toBe(291);
            } else {
                expect.fail('Expected blobVersion to be 1 for V1 KeyInfo JSON');
            }
        });
    });

    describe('Version 2 Blob', () => {
        // V2 KeyInfo: 32(fp) + 2(flags) + 2(RFU) + 20(keygrip) = 56 bytes. keyInfoStructSize = 56.
        const v2KeyInfoData = hexToUint8Array(
            '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20' + // fingerprintV2 (32 bytes)
            '0080' +     // keyFlags (is32ByteFingerprintInUse = true)
            '0000' +     // RFU
            'AABBCCDDEEFF00112233445566778899AABBCCDD'  // keygrip (20 bytes)
        );
        const v2StructSize = 56;

        it('should parse V2 KeyInfo correctly', () => {
            keyboxData.set(v2KeyInfoData, 0);
            const keyInfo = new KeyInfo(keyboxData, 0, v2StructSize, 2);

            expect(keyInfo.actualSizeInBlob).toBe(v2StructSize);
            expect(keyInfo.fingerprintV2).toEqual(hexToUint8Array('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'));
            expect(keyInfo.keyFlagsRaw).toEqual(hexToUint8Array('0080'));
            expect(keyInfo.keyFlagsParsed.qualifiedSignature).toBe(false);
            expect(keyInfo.keyFlagsParsed.is32ByteFingerprintInUse).toBe(true);
            expect(keyInfo.keygrip).toEqual(hexToUint8Array('AABBCCDDEEFF00112233445566778899AABBCCDD'));
            expect(keyInfo.fingerprintV1).toBeUndefined();
            expect(keyInfo.offsetKeyID).toBeUndefined();
        });

        it('should produce correct JSON for V2', () => {
            keyboxData.set(v2KeyInfoData, 0);
            const keyInfo = new KeyInfo(keyboxData, 0, v2StructSize, 2);
            const json = keyInfo.toJSON();

            expect(json.blobVersion).toBe(2); // Explicitly check the discriminant
            if (json.blobVersion === 2) {
                expect(json.fingerprintV2).toBe('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
                expect(json.keygrip).toBe('aabbccddeeff00112233445566778899aabbccdd'); // Buffer.from(...).toString('hex') lowercases
            } else {
                expect.fail('Expected blobVersion to be 2 for V2 KeyInfo JSON');
            }
        });
    });

    it('should throw for unsupported parent blob version', () => {
        expect(() => new KeyInfo(keyboxData, 0, 28, 3)).toThrow('KeyInfo: Unsupported parent blob version: 3');
    });
});
