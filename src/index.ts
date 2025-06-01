
import * as fs from 'node:fs/promises';
import { Buffer } from 'buffer'; // Node.js Buffer
import { IKeyboxFile, IPacket, IKeyInfo, IUserId, ISignatureExpirationTime } from './types.js';
import { FirstBlock } from './models/FirstBlock.js';
import { KeyBlockHeader } from './models/KeyBlock.js';
import { KeyInfo } from './models/KeyInfo.js';
import { UserIdInfo } from './models/UserIdInfo.js';
import { UserId } from './models/UserId.js';
import { SignatureInfoBlock } from './models/SignatureInfoBlock.js';
import { SignatureExpirationTime } from './models/SignatureExpirationTime.js';
import { BlockTrailingData } from './models/BlockTrailingData.js';
import { BasePacket } from './models/packets/BasePacket.js';
import { CHECKSUM_SIZE, USER_ID_STRUCTURE_SIZE, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE } from './constants.js';
import { sliceUint8Array } from './utils/parserUtils.js';

export default async function ReadKeybox(kbxFilePath: string): Promise<IKeyboxFile> {
    const kbxUint8Array = await fs.readFile(kbxFilePath).then(data => Uint8Array.from(data));

    const parsedFile: IKeyboxFile = {} as IKeyboxFile;
    let currentFileOffset = 0;

    // 1. Parse First Block
    const firstBlock = new FirstBlock(kbxUint8Array, currentFileOffset);
    parsedFile.firstBlock = firstBlock;
    currentFileOffset += firstBlock.blobLength; // Use actual blobLength from its field

    // Assuming one Data Blob (OpenPGP or X.509) follows the First Block
    // If multiple data blobs are possible, this part would need to loop or be more dynamic
    if (currentFileOffset < kbxUint8Array.length) {
        const dataBlobOffsetStart = currentFileOffset;

        // 2. Parse Key Block Header (for the OpenPGP/X.509 data blob)
        const keyBlockHeader = new KeyBlockHeader(kbxUint8Array, dataBlobOffsetStart);
        let internalBlobOffset = keyBlockHeader.structureLength; // Relative to dataBlobOffsetStart

        // 3. Parse Key Info array
        const keysInfo: IKeyInfo[] = [];
        for (let i = 0; i < keyBlockHeader.numKeys; i++) {
            const keyInfoEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            const keyInfo = new KeyInfo(kbxUint8Array, keyInfoEntryOffset, keyBlockHeader.keyInfoSize, keyBlockHeader.version);
            keysInfo.push(keyInfo);
            internalBlobOffset += keyBlockHeader.keyInfoSize; // Each KeyInfo structure has this size
        }

        // 4. Parse User ID Info block
        const userIdInfoOffset = dataBlobOffsetStart + internalBlobOffset;
        const userIdInfo = new UserIdInfo(kbxUint8Array, userIdInfoOffset);
        internalBlobOffset += userIdInfo.structureLength;
        
        // Serial Number data (if any) would be after KeyInfo array and before UserIdInfo if sizeSerialNumber > 0
        // The current internalBlobOffset calculation should correctly position after serial number if it exists
        // because `userIdInfoOffset` is `dataBlobOffsetStart + internalBlobOffset` *after* KeyInfo array.
        // If `userIdInfo.sizeSerialNumber > 0`, those bytes are between KeyInfo array end and UserIdInfo start.
        // The `UserIdInfo` constructor itself doesn't use `sizeSerialNumber` for its internal offsets.
        // Let's adjust: The serial number bytes are *before* UserIdInfo struct.
        // This line assumes serial number data directly follows KeyInfo array and *precedes* UserIdInfo struct.
        // If UserIdInfo was constructed at dataBlobOffsetStart + internalBlobOffset (after keyInfos),
        // and then we add sizeSerialNumber, this would place the serial number data *after* UserIdInfo struct,
        // which might be incorrect based on typical GPG structure (SN often between KeyInfos and UIDs).
        // However, the structure is: KeyInfos -> SerialNumberData (if present) -> UserIdInfoStruct -> UserIDEntries
        // The UserIdInfo object is parsed at `userIdInfoOffset`, which is correct.
        // The `internalBlobOffset` is then advanced by `userIdInfo.structureLength`.
        // *Then* we account for the serial number data. This seems correct: its location is implicitly handled by `userIdInfoOffset`
        // and its size is now explicitly added to `internalBlobOffset` to correctly position for the next block.
        internalBlobOffset += userIdInfo.sizeSerialNumber; 


        // 5. Parse User ID array
        const userIds: IUserId[] = [];
        for (let i = 0; i < userIdInfo.numUserIDs; i++) {
            const userIdEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            // UserId structure itself is fixed (12 bytes), but the entry for it in blob uses sizeUserIDInfoStructure
            const userId = new UserId(kbxUint8Array, userIdEntryOffset, userIdInfo.sizeUserIDInfoStructure);
            userIds.push(userId);
            internalBlobOffset += userIdInfo.sizeUserIDInfoStructure; // Each UserId entry uses this size
        }


        // 6. Parse Signature Info Block
        const signatureInfoBlockOffset = dataBlobOffsetStart + internalBlobOffset;
        const signatureInfoBlock = new SignatureInfoBlock(kbxUint8Array, signatureInfoBlockOffset);
        internalBlobOffset += signatureInfoBlock.structureLength;

        // 7. Parse Signature Expiration Time array
        const sigExpirationTimes: ISignatureExpirationTime[] = [];
        for (let i = 0; i < signatureInfoBlock.numSignatures; i++) {
            const sigExpTimeEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            const sigExpTime = new SignatureExpirationTime(kbxUint8Array, sigExpTimeEntryOffset, signatureInfoBlock.sizeSignatureInfoStructure);
            sigExpirationTimes.push(sigExpTime);
            internalBlobOffset += signatureInfoBlock.sizeSignatureInfoStructure; // Each entry uses this size
        }

        // 8. Parse Block Trailing Data
        const blockTrailingDataOffset = dataBlobOffsetStart + internalBlobOffset;
        const blockTrailingData = new BlockTrailingData(kbxUint8Array, blockTrailingDataOffset);
        internalBlobOffset += blockTrailingData.structureLength;

        // At this point, internalBlobOffset is after all fixed metadata structures within the data blob header region.
        // It should point to where "Reserved Space (NRES)" begins.
        // The actual PGP packets are at an offset specified by keyBlockHeader.offsetKeyblock relative to dataBlobOffsetStart.

        // 9. Parse Packets
        const packets: IPacket[] = [];
        let currentPacketParseOffset = dataBlobOffsetStart + keyBlockHeader.offsetKeyblock;
        const packetDataEndOffset = currentPacketParseOffset + keyBlockHeader.lengthKeyblock;

        while (currentPacketParseOffset < packetDataEndOffset) {
            if (currentPacketParseOffset >= kbxUint8Array.length) {
                 console.warn("Packet parsing attempting to read beyond end of file.");
                 break;
            }
            try {
                const packet = new BasePacket(kbxUint8Array, currentPacketParseOffset);
                packets.push(packet);
                currentPacketParseOffset += packet.totalPacketLength;
                if (packet.totalPacketLength === 0) { // Should not happen with definite lengths
                    console.error("Parsed a packet with zero length. Stopping packet parsing.");
                    break;
                }
            } catch (e: any) {
                console.error(`Error parsing packet at offset ${currentPacketParseOffset}: ${e.message}. Attempting to skip or stop.`, e.stack);
                // Basic recovery: try to find next valid packet start if possible, or break.
                // For now, just break to avoid infinite loops on malformed data.
                break; 
            }
        }
        
        // 10. Read Checksum from the end of this data blob
        const checksumOffset = dataBlobOffsetStart + keyBlockHeader.blobLength - CHECKSUM_SIZE;
        let checksum = new Uint8Array(0);
        if (checksumOffset >=0 && checksumOffset + CHECKSUM_SIZE <= kbxUint8Array.length) {
             checksum = new Uint8Array(sliceUint8Array(kbxUint8Array, checksumOffset, checksumOffset + CHECKSUM_SIZE));
        } else {
            console.warn("Could not read checksum, offset out of bounds.");
        }


        parsedFile.dataBlob = {
            header: keyBlockHeader,
            metadata: {
                keysInfo,
                userIdInfo,
                userIds,
                signatureInfoBlock,
                signatureExpirationTimes: sigExpirationTimes, // Corrected typo here
                blockTrailingData,
            },
            packets,
            checksum,
        };
        
        currentFileOffset = dataBlobOffsetStart + keyBlockHeader.blobLength; // Advance file offset past this entire data blob
    } else {
        console.log("No data blob found after First Block or file ends.");
    }
    
    if (currentFileOffset < kbxUint8Array.length) {
        console.warn(`ReadKeybox: ${kbxUint8Array.length - currentFileOffset} bytes remaining in file after parsing. File may contain additional blobs not handled by this parser.`);
    }

    // For debugging purposes, you can log the prettified structure:
    // console.log(JSON.stringify(parsedFile, (key, value) => {
    //     if (value instanceof Uint8Array) {
    //         return Buffer.from(value).toString('hex');
    //     }
    //     if (value && typeof value.toJSON === 'function') {
    //        return value.toJSON(kbxUint8Array); // Pass kbxUint8Array for UserId.toJSON
    //     }
    //     return value;
    // }, 2));

    return parsedFile;
}
