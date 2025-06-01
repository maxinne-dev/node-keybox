import { describe, it, expect, vi } from 'vitest';
import { UserId } from '../../models/UserId.js';
import { USER_ID_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('UserId', () => {
    const keyboxData = new Uint8Array(200); // Dummy larger buffer

    const validUserIdData = hexToUint8Array(
        '00000064' + // blobOffsetNthUserID (100)
        '0000000c' + // lengthThisUserID (12 bytes)
        '0001' +     // uidFlags
        '02'         // validity
    );

    it('should parse valid UserId data correctly', () => {
        keyboxData.set(validUserIdData, 0);
        const userId = new UserId(keyboxData, 0, USER_ID_STRUCTURE_SIZE);

        expect(userId.blobOffsetNthUserID).toBe(100);
        expect(userId.lengthThisUserID).toBe(12);
        expect(userId.uidFlags).toBe(1);
        expect(userId.validity).toBe(2);
        expect(userId.structureLength).toBe(USER_ID_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output without fullKbxData', () => {
        keyboxData.set(validUserIdData, 0);
        const userId = new UserId(keyboxData, 0, USER_ID_STRUCTURE_SIZE);
        const json = userId.toJSON();

        expect(json.blobOffsetNthUserID).toBe(100);
        expect(json.lengthThisUserID).toBe(12);
        expect(json.uidFlags).toBe(1);
        expect(json.validity).toBe(2);
        expect(json.structureLength).toBe(USER_ID_STRUCTURE_SIZE);
        expect(json).not.toHaveProperty('userIdString');
    });

    it('should produce correct JSON output with fullKbxData', () => {
        const userIdString = 'test@example.com';
        const userIdStringBytes = new TextEncoder().encode(userIdString);
        keyboxData.set(validUserIdData, 0);
        keyboxData.set(userIdStringBytes, 100); // Place the User ID string at offset 100

        const userId = new UserId(keyboxData, 0, USER_ID_STRUCTURE_SIZE);
        const json = userId.toJSON(keyboxData);

        expect(json.blobOffsetNthUserID).toBe(100);
        expect(json.lengthThisUserID).toBe(12);
        expect(json.uidFlags).toBe(1);
        expect(json.validity).toBe(2);
        expect(json.structureLength).toBe(USER_ID_STRUCTURE_SIZE);
    });

    it('should warn if expectedSizeUserIDInfoStructure does not match structureLength', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        new UserId(keyboxData, 0, USER_ID_STRUCTURE_SIZE + 2); // Pass a mismatched size
        expect(consoleWarnSpy).toHaveBeenCalledWith(
            `UserId: Parent indicated UserID structure size ${USER_ID_STRUCTURE_SIZE + 2}, but this class parses fixed ${USER_ID_STRUCTURE_SIZE} bytes. Ensure this is intended.`
        );
        consoleWarnSpy.mockRestore();
    });

    it('should handle out-of-bounds User ID string gracefully', () => {
        keyboxData.set(validUserIdData, 0);
        const userId = new UserId(keyboxData, 0, USER_ID_STRUCTURE_SIZE);

        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const userIdString = userId.getUserIDString(new Uint8Array(50)); // Pass a smaller buffer
        expect(consoleErrorSpy).toHaveBeenCalledWith('UserID string data out of bounds.');
        expect(userIdString).toBe('Error: UserID data out of bounds');
        consoleErrorSpy.mockRestore();
    });
});
