
import { describe, it, expect } from 'vitest';
import { BlockTrailingData } from '../../models/BlockTrailingData.js';
import { BLOCK_TRAILING_DATA_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('BlockTrailingData', () => {
    const validDataHex = 
        '01' +       // ownerTrust (1)
        '12' +       // allValidity (0x12 -> 0b00010010 -> keyRevoked = true)
        '0000' +     // RFU
        '0000000A' + // recheckAfter (10)
        '61F0C801' + // latestTimestamp
        '61F0C802' + // blobCreatedAtTimestamp
        '00000005';  // sizeReservedSpace (5)
    const validDataBytes = hexToUint8Array(validDataHex);
    const keyboxData = new Uint8Array(100); // Dummy larger buffer

    it('should parse valid BlockTrailingData correctly', () => {
        keyboxData.set(validDataBytes, 0);
        const trailingData = new BlockTrailingData(keyboxData, 0);

        expect(trailingData.ownerTrust).toBe(0x01);
        expect(trailingData.allValidity).toBe(0x12);
        expect(trailingData.allValidityParsed?.keyRevoked).toBe(true); 
        expect(trailingData.recheckAfter).toBe(10);
        expect(trailingData.latestTimestamp).toBe(0x61F0C801);
        expect(trailingData.blobCreatedAtTimestamp).toBe(0x61F0C802);
        expect(trailingData.blobCreatedAtDate).toEqual(new Date(0x61F0C802 * 1000));
        expect(trailingData.sizeReservedSpace).toBe(5);
        expect(trailingData.structureLength).toBe(BLOCK_TRAILING_DATA_STRUCTURE_SIZE);
    });

    it('should correctly parse allValidity when keyRevoked bit is not set', () => {
        const dataNoRevokeHex = 
            '01' + '02' + '0000' + '0000000A' + '61F0C801' + '61F0C802' + '00000005';
        const dataNoRevokeBytes = hexToUint8Array(dataNoRevokeHex);
        keyboxData.set(dataNoRevokeBytes, 0);
        const trailingData = new BlockTrailingData(keyboxData, 0);
        
        expect(trailingData.allValidity).toBe(0x02);
        expect(trailingData.allValidityParsed?.keyRevoked).toBe(false);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validDataBytes, 0);
        const trailingData = new BlockTrailingData(keyboxData, 0);
        const json = trailingData.toJSON();

        expect(json.ownerTrust).toBe(0x01);
        expect(json.allValidity).toBe(0x12);
        expect(json.allValidityParsed?.keyRevoked).toBe(true);
        expect(json.blobCreatedAtDate).toBe(new Date(0x61F0C802 * 1000).toISOString());
        expect(json.structureLength).toBe(BLOCK_TRAILING_DATA_STRUCTURE_SIZE);
    });
    
    it('should handle parsing from an offset within keyboxData', () => {
        const offset = 5;
        keyboxData.set(validDataBytes, offset);
        const trailingData = new BlockTrailingData(keyboxData, offset);

        expect(trailingData.ownerTrust).toBe(0x01);
        expect(trailingData.latestTimestamp).toBe(0x61F0C801);
    });
});
