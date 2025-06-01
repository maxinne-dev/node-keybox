
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
import { CHECKSUM_SIZE } from './constants.js';
import { sliceUint8Array, sha1Hash } from './utils/parserUtils.js';
import { Buffer } from 'buffer';


export class KeyboxParser {
    private kbxUint8Array: Uint8Array;
    private currentFileOffset: number = 0;
    private parsedFile: IKeyboxFile;

    constructor(kbxData: Uint8Array) {
        this.kbxUint8Array = kbxData;
        this.parsedFile = {} as IKeyboxFile;
    }

    public parse(): IKeyboxFile {
        // 1. Parse First Block
        const firstBlock = new FirstBlock(this.kbxUint8Array, this.currentFileOffset);
        this.parsedFile.firstBlock = firstBlock;
        this.currentFileOffset += firstBlock.blobLength;

        // Assuming one Data Blob (OpenPGP or X.509) follows the First Block
        if (this.currentFileOffset < this.kbxUint8Array.length) {
            this.parseDataBlob();
        } else {
            console.log("No data blob found after First Block or file ends.");
        }
        
        if (this.currentFileOffset < this.kbxUint8Array.length) {
            console.warn(`KeyboxParser: ${this.kbxUint8Array.length - this.currentFileOffset} bytes remaining in file after parsing. File may contain additional blobs not handled by this parser.`);
        }

        return this.parsedFile;
    }

    private parseDataBlob(): void {
        const dataBlobOffsetStart = this.currentFileOffset;

        // 2. Parse Key Block Header
        const keyBlockHeader = new KeyBlockHeader(this.kbxUint8Array, dataBlobOffsetStart);
        let internalBlobOffset = keyBlockHeader.structureLength;

        // 3. Parse Key Info array
        const keysInfo: IKeyInfo[] = [];
        for (let i = 0; i < keyBlockHeader.numKeys; i++) {
            const keyInfoEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            const keyInfo = new KeyInfo(this.kbxUint8Array, keyInfoEntryOffset, keyBlockHeader.keyInfoSize, keyBlockHeader.version);
            keysInfo.push(keyInfo);
            internalBlobOffset += keyBlockHeader.keyInfoSize;
        }

        // 4. Parse User ID Info block and account for Serial Number data
        const userIdInfoOffset = dataBlobOffsetStart + internalBlobOffset;
        const userIdInfo = new UserIdInfo(this.kbxUint8Array, userIdInfoOffset);
        internalBlobOffset += userIdInfo.structureLength;
        internalBlobOffset += userIdInfo.sizeSerialNumber; // Serial number data (if any) is after KeyInfos and before UserID entries

        // 5. Parse User ID array
        const userIds: IUserId[] = [];
        for (let i = 0; i < userIdInfo.numUserIDs; i++) {
            const userIdEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            const userId = new UserId(this.kbxUint8Array, userIdEntryOffset, userIdInfo.sizeUserIDInfoStructure);
            userIds.push(userId);
            internalBlobOffset += userIdInfo.sizeUserIDInfoStructure;
        }

        // 6. Parse Signature Info Block
        const signatureInfoBlockOffset = dataBlobOffsetStart + internalBlobOffset;
        const signatureInfoBlock = new SignatureInfoBlock(this.kbxUint8Array, signatureInfoBlockOffset);
        internalBlobOffset += signatureInfoBlock.structureLength;

        // 7. Parse Signature Expiration Time array
        const sigExpirationTimes: ISignatureExpirationTime[] = [];
        for (let i = 0; i < signatureInfoBlock.numSignatures; i++) {
            const sigExpTimeEntryOffset = dataBlobOffsetStart + internalBlobOffset;
            const sigExpTime = new SignatureExpirationTime(this.kbxUint8Array, sigExpTimeEntryOffset, signatureInfoBlock.sizeSignatureInfoStructure);
            sigExpirationTimes.push(sigExpTime);
            internalBlobOffset += signatureInfoBlock.sizeSignatureInfoStructure;
        }

        // 8. Parse Block Trailing Data
        const blockTrailingDataOffset = dataBlobOffsetStart + internalBlobOffset;
        const blockTrailingData = new BlockTrailingData(this.kbxUint8Array, blockTrailingDataOffset);
        internalBlobOffset += blockTrailingData.structureLength;

        // 9. Parse Packets
        const packets: IPacket[] = [];
        let currentPacketParseOffset = dataBlobOffsetStart + keyBlockHeader.offsetKeyblock;
        const packetDataEndOffset = currentPacketParseOffset + keyBlockHeader.lengthKeyblock;

        while (currentPacketParseOffset < packetDataEndOffset) {
            if (currentPacketParseOffset >= this.kbxUint8Array.length) {
                 console.warn("Packet parsing attempting to read beyond end of file.");
                 break;
            }
            try {
                const packet = new BasePacket(this.kbxUint8Array, currentPacketParseOffset);
                packets.push(packet);
                currentPacketParseOffset += packet.totalPacketLength;
                if (packet.totalPacketLength === 0) {
                    console.error("Parsed a packet with zero length. Stopping packet parsing.");
                    break;
                }
            } catch (e: any) {
                console.error(`Error parsing packet at offset ${currentPacketParseOffset}: ${e.message}. Attempting to skip or stop.`, e.stack);
                break; 
            }
        }
        
        // 10. Read and Verify Checksum
        const checksumOffset = dataBlobOffsetStart + keyBlockHeader.blobLength - CHECKSUM_SIZE;
        let checksum = new Uint8Array(0);
        let isChecksumValid: boolean | undefined = undefined;

        if (keyBlockHeader.blobLength >= CHECKSUM_SIZE && 
            checksumOffset >=0 && 
            checksumOffset + CHECKSUM_SIZE <= this.kbxUint8Array.length &&
            dataBlobOffsetStart + keyBlockHeader.blobLength <= this.kbxUint8Array.length) {
            
            checksum = sliceUint8Array(this.kbxUint8Array, checksumOffset, checksumOffset + CHECKSUM_SIZE);
            
            if (keyBlockHeader.blobLength > CHECKSUM_SIZE) { // Ensure there's data to checksum
                 const dataToChecksum = sliceUint8Array(this.kbxUint8Array, dataBlobOffsetStart, checksumOffset);
                 const calculatedChecksum = sha1Hash(dataToChecksum);
                 isChecksumValid = Buffer.from(calculatedChecksum).equals(Buffer.from(checksum));
                 if (!isChecksumValid) {
                     console.warn(`Data blob checksum mismatch. Expected ${Buffer.from(checksum).toString('hex')}, calculated ${Buffer.from(calculatedChecksum).toString('hex')}`);
                 }
            } else {
                // If blobLength is exactly CHECKSUM_SIZE, dataToChecksum would be empty.
                // An empty data typically results in a known hash, but GnuPG might not create such blobs.
                // For now, we'll mark checksum as not validated or potentially invalid.
                isChecksumValid = false; // Or undefined, based on desired behavior for edge case
                console.warn("Data blob length is equal to checksum size, cannot verify checksum of preceding data.");
            }
        } else {
            console.warn("Could not read or verify checksum, offset out of bounds or blob too short.");
        }

        this.parsedFile.dataBlob = {
            header: keyBlockHeader,
            metadata: {
                keysInfo,
                userIdInfo,
                userIds,
                signatureInfoBlock,
                signatureExpirationTimes: sigExpirationTimes,
                blockTrailingData,
            },
            packets,
            checksum,
            isChecksumValid,
        };
        
        this.currentFileOffset = dataBlobOffsetStart + keyBlockHeader.blobLength;
    }
}
