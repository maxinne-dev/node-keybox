import { describe, it, expect, vi } from 'vitest';
import { KeyBlockHeader } from '../../models/KeyBlock.js';
import { KEY_BLOCK_HEADER_STRUCTURE_SIZE, BLOB_TYPE_OPENPGP } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('KeyBlockHeader', () => {
    const validOpenPGPData = hexToUint8Array(
        '00000100' + // blobLength (256 bytes)
        '02' +       // type (OpenPGP)
        '01' +       // version (v1 - 20 byte fingerprints)
        '0000' +     // blobFlags
        '00000020' + // offsetKeyblock (32)
        '000000c0' + // lengthKeyblock (192)
        '0001' +     // numKeys (1)
        '001c'       // keyInfoSize (28 bytes for v1)
    );

    it('should parse valid OpenPGP KeyBlockHeader data correctly', () => {
        const header = new KeyBlockHeader(validOpenPGPData, 0);

        expect(header.blobLength).toBe(256);
        expect(header.type).toBe(BLOB_TYPE_OPENPGP);
        expect(header.version).toBe(1);
        expect(header.blobFlags).toBe(0);
        expect(header.offsetKeyblock).toBe(32);
        expect(header.lengthKeyblock).toBe(192);
        expect(header.numKeys).toBe(1);
        expect(header.keyInfoSize).toBe(28);
        expect(header.structureLength).toBe(KEY_BLOCK_HEADER_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        const header = new KeyBlockHeader(validOpenPGPData, 0);
        const json = header.toJSON();
        expect(json.type).toBe(BLOB_TYPE_OPENPGP);
        expect(json.numKeys).toBe(1);
    });

    it('should warn for unexpected blob type', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const modifiedData = new Uint8Array(validOpenPGPData);
        modifiedData[4] = 0x05; // Unexpected type
        new KeyBlockHeader(modifiedData, 0);
        expect(consoleWarnSpy).toHaveBeenCalledWith('KeyBlockHeader: Unexpected blob type 5. Expected 2 (OpenPGP) or 3 (X.509).');
        consoleWarnSpy.mockRestore();
    });
});
