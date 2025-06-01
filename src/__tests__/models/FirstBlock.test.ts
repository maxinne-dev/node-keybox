import { describe, it, expect, vi } from 'vitest';
import { FirstBlock } from '../../models/FirstBlock.js';
import { FIRST_BLOB_MAGIC, FIRST_BLOB_STRUCTURE_SIZE, BLOB_TYPE_FIRST, FIRST_BLOB_VERSION } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('FirstBlock', () => {
    const validData = hexToUint8Array(
        '00000020' + // blobLength (32 bytes)
        '01' +       // blobType (1)
        '01' +       // blobVersion (1)
        '0002' +     // headerFlags (Is OpenPGP)
        '4b425866' + // magic 'KBXf'
        '00000000' + // RFU
        '61f0c800' + // createdAtTimestamp (2022-01-25T12:00:00.000Z)
        '61f0c800' + // maintainedAtTimestamp
        '00000000' + // RFU
        '00000000'   // RFU
    );

    it('should parse valid FirstBlock data correctly', () => {
        const firstBlock = new FirstBlock(validData, 0);

        expect(firstBlock.blobLength).toBe(FIRST_BLOB_STRUCTURE_SIZE);
        expect(firstBlock.blobType).toBe(BLOB_TYPE_FIRST);
        expect(firstBlock.blobVersion).toBe(FIRST_BLOB_VERSION);
        expect(firstBlock.headerFlags).toBe(0x0002);
        expect(firstBlock.magic).toBe(FIRST_BLOB_MAGIC);
        expect(firstBlock.createdAtTimestamp).toBe(0x61f0c800);
        expect(firstBlock.maintainedAtTimestamp).toBe(0x61f0c800);
        expect(firstBlock.createdDate).toEqual(new Date(0x61f0c800 * 1000));
        expect(firstBlock.lastMaintainedDate).toEqual(new Date(0x61f0c800 * 1000));
        expect(firstBlock.structureLength).toBe(FIRST_BLOB_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        const firstBlock = new FirstBlock(validData, 0);
        const json = firstBlock.toJSON();
        expect(json.magic).toBe(FIRST_BLOB_MAGIC);
        expect(json.blobLength).toBe(FIRST_BLOB_STRUCTURE_SIZE);
        expect(json.createdDate).toBe(new Date(0x61f0c800 * 1000).toISOString());
    });

    it('should warn if blobType is incorrect', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const modifiedData = new Uint8Array(validData);
        modifiedData[4] = 0x02; // Incorrect blobType
        new FirstBlock(modifiedData, 0);
        expect(consoleWarnSpy).toHaveBeenCalledWith('FirstBlock: Expected blob type 1, got 2');
        consoleWarnSpy.mockRestore();
    });

    it('should warn if magic is incorrect', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const modifiedData = hexToUint8Array(
            '0000002001010002' + '4b42584B' + '0000000061f0c80061f0c8000000000000000000' // 'KBXK'
        );
        new FirstBlock(modifiedData, 0);
        expect(consoleWarnSpy).toHaveBeenCalledWith("FirstBlock: Expected magic 'KBXf', got 'KBXK'");
        consoleWarnSpy.mockRestore();
    });
    
    it('should warn if blobLength field does not match structureSize', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const modifiedData = hexToUint8Array(
            '00000021' + // blobLength (33 bytes - incorrect)
            '01' +       // blobType (1)
            '01' +       // blobVersion (1)
            '0002' +     // headerFlags
            '4b425866' + // magic 'KBXf'
            '00000000' + // RFU
            '61f0c800' + // createdAtTimestamp
            '61f0c800' + // maintainedAtTimestamp
            '00000000' + // RFU
            '00000000'   // RFU
        );
        new FirstBlock(modifiedData, 0);
        expect(consoleWarnSpy).toHaveBeenCalledWith(`FirstBlock: Blob length field (33) does not match expected structure size (${FIRST_BLOB_STRUCTURE_SIZE}). File might be non-standard.`);
        consoleWarnSpy.mockRestore();
    });

});
