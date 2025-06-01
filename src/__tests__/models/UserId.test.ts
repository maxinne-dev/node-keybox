
import { describe, it, expect, vi } from 'vitest';
import { UserId } from '../../models/UserId.js';
import { USER_ID_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';
import { Buffer } from 'buffer';

describe('UserId', () => {
    const fullKbxData = new Uint8Array(200); // A larger buffer representing the whole KBX file
    const userIdString = "Test User <test@example.com>";
    const userIdStringBytes = Buffer.from(userIdString, 'utf8');
    
    // Place the string at a specific offset in the full KBX data
    const stringOffsetInKbx = 50;
    fullKbxData.set(userIdStringBytes, stringOffsetInKbx);

    const validUserIdMetadataHex = 
        stringOffsetInKbx.toString(16).padStart(8, '0') +   // blobOffsetNthUserID
        userIdStringBytes.length.toString(16).padStart(8, '0') + // lengthThisUserID
        '00A1' + // uidFlags
        'B2' +   // validity
        '00';    // RFU
    const validUserIdMetadataBytes = hexToUint8Array(validUserIdMetadataHex);
    
    const metadataOffsetInKbx = 0; // For simplicity, the metadata itself is at offset 0 in its own parsing context
                                   // but its blobOffsetNthUserID points into fullKbxData

    it('should parse valid UserId metadata correctly', () => {
        const userId = new UserId(validUserIdMetadataBytes, metadataOffsetInKbx, USER_ID_STRUCTURE_SIZE);

        expect(userId.blobOffsetNthUserID).toBe(stringOffsetInKbx);
        expect(userId.lengthThisUserID).toBe(userIdStringBytes.length);
        expect(userId.uidFlags).toBe(0x00A1);
        expect(userId.validity).toBe(0xB2);
        expect(userId.structureLength).toBe(USER_ID_STRUCTURE_SIZE);
    });

    it('should retrieve the User ID string correctly', () => {
        const userId = new UserId(validUserIdMetadataBytes, metadataOffsetInKbx, USER_ID_STRUCTURE_SIZE);
        expect(userId.getUserIDString(fullKbxData)).toBe(userIdString);
    });

    it('should handle User ID string out of bounds gracefully', () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const invalidMetadataHex = 
            (fullKbxData.length + 10).toString(16).padStart(8, '0') + // blobOffsetNthUserID out of bounds
            '00000005' + // lengthThisUserID
            '0000' + '00' + '00';
        const invalidMetadataBytes = hexToUint8Array(invalidMetadataHex);
        const userId = new UserId(invalidMetadataBytes, 0, USER_ID_STRUCTURE_SIZE);
        
        expect(userId.getUserIDString(fullKbxData)).toBe("Error: UserID data out of bounds");
        expect(consoleErrorSpy).toHaveBeenCalledWith("UserID string data out of bounds.");
        consoleErrorSpy.mockRestore();
    });
    
    it('should produce correct JSON output without string if fullKbxData not provided', () => {
        const userId = new UserId(validUserIdMetadataBytes, metadataOffsetInKbx, USER_ID_STRUCTURE_SIZE);
        const json = userId.toJSON();

        expect(json.blobOffsetNthUserID).toBe(stringOffsetInKbx);
        expect(json.lengthThisUserID).toBe(userIdStringBytes.length);
        expect((json as any).userIdString).toBeUndefined();
    });

    it('should produce correct JSON output with string if fullKbxData is provided', () => {
        const userId = new UserId(validUserIdMetadataBytes, metadataOffsetInKbx, USER_ID_STRUCTURE_SIZE);
        const json = userId.toJSON(fullKbxData);

        expect(json.blobOffsetNthUserID).toBe(stringOffsetInKbx);
        expect(json.lengthThisUserID).toBe(userIdStringBytes.length);
        expect((json as { userIdString: string }).userIdString).toBe(userIdString);
    });

    it('should warn if expectedSizeUserIDInfoStructure differs from fixed structureLength', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        new UserId(validUserIdMetadataBytes, metadataOffsetInKbx, USER_ID_STRUCTURE_SIZE + 4); // Expected size is larger
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`UserId: Parent indicated UserID structure size ${USER_ID_STRUCTURE_SIZE + 4}, but this class parses fixed ${USER_ID_STRUCTURE_SIZE} bytes. Ensure this is intended.`);
        consoleWarnSpy.mockRestore();
    });
});
