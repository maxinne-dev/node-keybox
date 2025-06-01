
import { describe, it, expect } from 'vitest';
import { TrustPacketData } from '../../../models/packets/TrustPacketData.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('TrustPacketData', () => {
    const keyboxData = new Uint8Array(100); // Dummy buffer

    it('should parse trust data correctly', () => {
        const trustDataHex = "0102030405060708090a"; // 10 bytes of trust data
        const trustDataBytes = hexToUint8Array(trustDataHex);
        
        keyboxData.set(trustDataBytes, 5); // Store at an offset
        const tpData = new TrustPacketData(keyboxData, 5, trustDataBytes.length);

        expect(tpData.trustData).toEqual(trustDataBytes);
    });

    it('should handle empty trust data', () => {
        const trustDataBytes = new Uint8Array(0);
        
        const tpData = new TrustPacketData(keyboxData, 0, trustDataBytes.length);

        expect(tpData.trustData).toEqual(trustDataBytes);
        expect(tpData.trustData.length).toBe(0);
    });

    it('should produce correct JSON output', () => {
        const trustDataHex = "aabbccddeeff";
        const trustDataBytes = hexToUint8Array(trustDataHex);
        
        keyboxData.set(trustDataBytes, 0);
        const tpData = new TrustPacketData(keyboxData, 0, trustDataBytes.length);
        const json = tpData.toJSON();

        expect(json.trustData_hex).toBe(trustDataHex);
        expect(json.trustData_length).toBe(trustDataBytes.length);
    });
});
