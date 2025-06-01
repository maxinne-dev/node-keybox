
import { Buffer } from 'buffer';
import { IUserId, TCursor, TRawUserIdKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { USER_ID_STRUCTURE_SIZE } from '../constants.js';
import { readUInt32BE, readUInt16BE, readUInt8 } from '../utils/parserUtils.js';

type UserIdRawData = Record<TRawUserIdKeys, Uint8Array>;

export class UserId extends TBlob implements IUserId {
    private readonly _rawData: UserIdRawData;
    public readonly structureLength: number = USER_ID_STRUCTURE_SIZE; // This specific structure is 12 bytes

    // The actual User ID string data, if fetched, would be stored separately or fetched on demand.
    // This class parses the 12-byte metadata structure for a User ID.

    private static readonly _positions: Record<TRawUserIdKeys, TCursor> = {
        blobOffsetNthUserID: [0, 4], // Offset to the User ID string data from start of KBX file
        lengthThisUserID: [4, 8],    // Length of the User ID string data
        uidFlags: [8, 10],
        validity: [10, 11],
        // RFU: [11, 12]
    };

    constructor(keyboxData: Uint8Array, blobOffset: number, expectedSizeUserIDInfoStructure: number) {
        super(keyboxData, blobOffset); // blobOffset is the start of this specific UserId entry

        if (expectedSizeUserIDInfoStructure !== this.structureLength) {
            // The spec says "Size of user ID information structure". If it's not 12, it might include RFU or other data.
            // For now, we parse the defined 12 bytes.
            // This class assumes the structure it's parsing IS 12 bytes, as per defined fields.
            // The `expectedSizeUserIDInfoStructure` from parent UserIdInfo is for the *entire entry* for one UID.
            // If it's > 12, the extra bytes are RFU/filler for that entry.
            console.warn(`UserId: Parent indicated UserID structure size ${expectedSizeUserIDInfoStructure}, but this class parses fixed ${this.structureLength} bytes. Ensure this is intended.`);
        }
        
        const rawDataEntries = Object.entries(UserId._positions) as [TRawUserIdKeys, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as UserIdRawData);
    }

    get blobOffsetNthUserID(): number {
        return readUInt32BE(this._rawData.blobOffsetNthUserID);
    }

    get lengthThisUserID(): number {
        return readUInt32BE(this._rawData.lengthThisUserID);
    }

    get uidFlags(): number {
        return readUInt16BE(this._rawData.uidFlags);
    }

    get validity(): number {
        return readUInt8(this._rawData.validity);
    }
    
    // Method to get the actual User ID string (name, email, etc.)
    // This requires reading from _kbx at blobOffsetNthUserID for lengthThisUserID bytes.
    public getUserIDString(fullKbxData: Uint8Array): string {
        const start = this.blobOffsetNthUserID;
        const end = start + this.lengthThisUserID;
        if (end > fullKbxData.length) {
            console.error("UserID string data out of bounds.");
            return "Error: UserID data out of bounds";
        }
        return Buffer.from(fullKbxData.subarray(start, end)).toString('utf8');
    }

    public toJSON(fullKbxData?: Uint8Array) {
        const base = {
            blobOffsetNthUserID: this.blobOffsetNthUserID,
            lengthThisUserID: this.lengthThisUserID,
            uidFlags: this.uidFlags,
            validity: this.validity,
            structureLength: this.structureLength,
        };
        if (fullKbxData) {
            return {...base, userIdString: this.getUserIDString(fullKbxData) };
        }
        return base;
    }
}
