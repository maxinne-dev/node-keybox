
import { describe, it, expect } from 'vitest';
import { SignatureSubpacket } from '../../../models/packets/SignatureSubpacket.js';
import { SignatureSubpacketType } from '../../../constants.js';
import { hexToUint8Array, u8 } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('SignatureSubpacket', () => {
    const keyboxData = new Uint8Array(512); // Dummy buffer for testing

    it('should parse a 1-octet length subpacket correctly (non-critical)', () => {
        // Length: 5 (0x05) (1 byte type + 4 bytes data)
        // Type: 2 (Signature Creation Time)
        // Data: 4 bytes timestamp
        const timestampHex = "61f0c800";
        const subpacketDataHex = "05" + "02" + timestampHex;
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);

        const subpacket = new SignatureSubpacket(keyboxData, 0, subpacketBytes.length);

        expect(subpacket.subpacketLength).toBe(5); // type + rawData
        expect(subpacket.totalSubpacketBytes).toBe(1 + 5); // length_field + type + rawData
        expect(subpacket.type).toBe(SignatureSubpacketType.SIGNATURE_CREATION_TIME);
        expect(subpacket.isCritical).toBe(false);
        expect(subpacket.rawData).toEqual(hexToUint8Array(timestampHex));
    });

    it('should parse a 1-octet length subpacket correctly (critical)', () => {
        // Length: 2 (0x02) (1 byte type + 1 byte data)
        // Type: 27 (Key Flags) | 0x80 (Critical) = 0x9B
        // Data: 1 byte flags
        const flagsHex = "01";
        const subpacketDataHex = "02" + "9B" + flagsHex;
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);

        const subpacket = new SignatureSubpacket(keyboxData, 0, subpacketBytes.length);

        expect(subpacket.subpacketLength).toBe(2);
        expect(subpacket.totalSubpacketBytes).toBe(1 + 2);
        expect(subpacket.type).toBe(SignatureSubpacketType.KEY_FLAGS);
        expect(subpacket.isCritical).toBe(true);
        expect(subpacket.rawData).toEqual(hexToUint8Array(flagsHex));
    });

    it('should parse a 2-octet length subpacket correctly', () => {
        // Length: 200 (0xC8). First octet: 192 + ((200-192)>>8) = 192 (0xC0). Second: (200-192)&0xFF = 8 (0x08)
        // Type: 20 (Notation Data)
        // Data: 199 bytes
        const notationDataHex = "AA".repeat(199);
        const subpacketDataHex = "C008" + "14" + notationDataHex; // 0x14 is type 20
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);

        const subpacket = new SignatureSubpacket(keyboxData, 0, subpacketBytes.length);
        expect(subpacket.subpacketLength).toBe(200);
        expect(subpacket.totalSubpacketBytes).toBe(2 + 200);
        expect(subpacket.type).toBe(SignatureSubpacketType.NOTATION_DATA);
        expect(subpacket.isCritical).toBe(false);
        expect(subpacket.rawData).toEqual(hexToUint8Array(notationDataHex));
    });

    it('should parse a 5-octet length subpacket correctly', () => {
        // Length: 70000 (0x00011170). First octet: 0xFF. Then 4 bytes length.
        // Type: 32 (Embedded Signature)
        // Data: 69999 bytes
        const embeddedSigHex = "BB".repeat(10); // Using small data for test run speed
        const subpacketDataHex = "FF0000000B" + "20" + embeddedSigHex; // Len 11 (1 type + 10 data)
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);

        const subpacket = new SignatureSubpacket(keyboxData, 0, subpacketBytes.length);
        expect(subpacket.subpacketLength).toBe(11);
        expect(subpacket.totalSubpacketBytes).toBe(5 + 11);
        expect(subpacket.type).toBe(SignatureSubpacketType.EMBEDDED_SIGNATURE);
        expect(subpacket.rawData).toEqual(hexToUint8Array(embeddedSigHex));
    });
    
    it('should throw if totalSubpacketBytes exceeds maxAvailableLength (1-octet length case)', () => {
        const subpacketDataHex = "05" + "02" + "61f0c800"; // Actual total 6 bytes
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);
        expect(() => new SignatureSubpacket(keyboxData, 0, 5)) // Provide only 5 bytes available
             .toThrow('SignatureSubpacket: Declared length 6 (field 1 + data 5) exceeds available data 5.');
    });

    it('should throw if subpacket content length is zero', () => {
        const subpacketDataHex = "00"; // Length 0
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);
        expect(() => new SignatureSubpacket(keyboxData, 0, 1))
            .toThrow('SignatureSubpacket: Subpacket content length is zero, too short for type.');
    });

    it('should produce correct JSON output', () => {
        const subpacketDataHex = "029B01"; // Critical Key Flags, data 0x01
        const subpacketBytes = hexToUint8Array(subpacketDataHex);
        keyboxData.set(subpacketBytes, 0);
        const subpacket = new SignatureSubpacket(keyboxData, 0, subpacketBytes.length);
        const json = subpacket.toJSON();

        expect(json.type).toBe('KEY_FLAGS');
        expect(json.typeId).toBe(SignatureSubpacketType.KEY_FLAGS);
        expect(json.isCritical).toBe(true);
        expect(json.rawData_hex).toBe('01');
    });
});
