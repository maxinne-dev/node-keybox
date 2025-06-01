
import { describe, it, expect } from 'vitest';
import { UserIdInfo } from '../../models/UserIdInfo.js';
import { USER_ID_INFO_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('UserIdInfo', () => {
    const validDataHex = 
        '000A' + // sizeSerialNumber (10)
        '0003' + // numUserIDs (3)
        '000C';  // sizeUserIDInfoStructure (12)
    const validDataBytes = hexToUint8Array(validDataHex);
    const keyboxData = new Uint8Array(100); // Dummy larger buffer

    it('should parse valid UserIdInfo data correctly', () => {
        keyboxData.set(validDataBytes, 0);
        const userIdInfo = new UserIdInfo(keyboxData, 0);

        expect(userIdInfo.sizeSerialNumber).toBe(10);
        expect(userIdInfo.numUserIDs).toBe(3);
        expect(userIdInfo.sizeUserIDInfoStructure).toBe(12);
        expect(userIdInfo.structureLength).toBe(USER_ID_INFO_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validDataBytes, 0);
        const userIdInfo = new UserIdInfo(keyboxData, 0);
        const json = userIdInfo.toJSON();

        expect(json.sizeSerialNumber).toBe(10);
        expect(json.numUserIDs).toBe(3);
        expect(json.sizeUserIDInfoStructure).toBe(12);
        expect(json.structureLength).toBe(USER_ID_INFO_STRUCTURE_SIZE);
    });

    it('should handle parsing from an offset within keyboxData', () => {
        const offset = 10;
        keyboxData.set(validDataBytes, offset);
        const userIdInfo = new UserIdInfo(keyboxData, offset);

        expect(userIdInfo.numUserIDs).toBe(3);
    });
});
