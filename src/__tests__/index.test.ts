/// <reference types="vitest" />

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fsPromises from 'node:fs/promises'; // Import the actual module
import ReadKeybox from '../index.js';
import { hexToUint8Array } from './test-utils.js';
import { FIRST_BLOB_MAGIC, BLOB_TYPE_OPENPGP, CHECKSUM_SIZE } from '../constants.js';
import { PacketTypeEnum } from '../types.js';
import { Buffer } from 'buffer';

// Mock the entire fs/promises module
vi.mock('node:fs/promises');

describe('ReadKeybox integration test', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Reset the mock for readFile before each test
        vi.mocked(fsPromises.readFile).mockReset();
    });

    it('should parse a minimal Keybox file with FirstBlock and one OpenPGP DataBlob', async () => {
        const firstBlockDataHex = 
            '00000020' + // blobLength (32)
            '01' +       // blobType (1)
            '01' +       // blobVersion (1)
            '0000' +     // headerFlags
            '4b425866' + // magic 'KBXf'
            '00000000' + // RFU
            '00000000' + // createdAt
            '00000000' + // maintainedAt
            '00000000' + // RFU
            '00000000';  // RFU
        
        const keyBlockHeaderHex = 
            '000000c8' + // blobLength (200 for data blob)
            '02' +       // type (OpenPGP)
            '01' +       // version (v1 keyinfo)
            '0000' +     // blobFlags
            '00000032' + // offsetKeyblock (50 - after KBH + metadata)
            '00000005' + // lengthKeyblock (5 for marker packet)
            '0000' +     // numKeys (0)
            '001c';      // keyInfoSize (28 for v1)
        
        const userIdInfoDataHex = '0000' + '0000' + '000c'; // sizeSN=0, numUIDs=0, sizeUIDstruct=12
        const signatureInfoBlockDataHex = '0000' + '0004'; // numSigs=0, sizeSigStruct=4
        const blockTrailingDataHex = '00' + '00' + '0000' + '00000000' + '00000000' + '00000000' + '00000000';
        
        const metadataHex = userIdInfoDataHex + signatureInfoBlockDataHex + blockTrailingDataHex; // 6 + 4 + 20 = 30 bytes
        
        // Marker packet: Tag(0xCA: type 10, new format), Length(0x03), Data('PGP': 504750)
        const packetDataHex = 'ca03504750'; // 5 bytes long
        
        // Checksum (20 bytes)
        const checksumHex = '842a34ff88e8cf04020c74d13282c9d9b02e9e08';

        // Data blob layout:
        // KeyBlockHeader (20 bytes)
        // Metadata (KeyInfo(0) + SN(0) + UserIDInfo(6) + UserIDs(0) + SigInfo(4) + SigExps(0) + Trailing(20)) = 30 bytes
        // Total Header/Metadata part = 20 + 30 = 50 bytes.
        // Packets start at offsetKeyblock from start of datablob. So packets start at 50 bytes from DataBlob start.
        // Packets lengthKeyblock = 5 bytes.
        // Remaining space = blobLength (200) - KBH (20) - Meta (30) - Packet (5) - Checksum (20)
        // = 200 - 50 - 5 - 20 = 125 bytes of padding between packets and checksum.
        
        const paddingAfterPacketsHex = 'bb'.repeat(125);

        const dataBlobContentHex = 
            keyBlockHeaderHex + 
            metadataHex +
            packetDataHex +
            paddingAfterPacketsHex +
            checksumHex;
            
        const fullFileHex = firstBlockDataHex + dataBlobContentHex;
        const mockFileDataBytes = hexToUint8Array(fullFileHex);
        
        vi.mocked(fsPromises.readFile).mockResolvedValue(Buffer.from(mockFileDataBytes));

        const result = await ReadKeybox('dummy/path.kbx');

        expect(result.firstBlock).toBeDefined();
        expect(result.firstBlock.magic).toBe(FIRST_BLOB_MAGIC);

        expect(result.dataBlob).toBeDefined();
        const dataBlob = result.dataBlob!;
        expect(dataBlob.header.type).toBe(BLOB_TYPE_OPENPGP);
        expect(dataBlob.header.numKeys).toBe(0);
        // offsetKeyblock is relative to start of dataBlob.
        // dataBlob starts after firstBlock (32 bytes).
        // KeyBlockHeader is 20. Metadata parsed is 30. Total 50.
        // So, keyBlockHeader.offsetKeyblock in the file is 50.
        expect(dataBlob.header.offsetKeyblock).toBe(50); 
        expect(dataBlob.header.lengthKeyblock).toBe(5);
        
        expect(dataBlob.metadata.keysInfo.length).toBe(0);
        expect(dataBlob.metadata.userIdInfo.numUserIDs).toBe(0);
        expect(dataBlob.metadata.signatureInfoBlock.numSignatures).toBe(0);
        
        expect(dataBlob.packets.length).toBe(1);
        expect(dataBlob.packets[0].tagInfo.packetType).toBe(PacketTypeEnum.MARKER);
        
        expect(dataBlob.checksum).toEqual(hexToUint8Array(checksumHex));
    });
});