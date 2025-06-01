
import { Buffer } from 'buffer';
import { IUserIdInfo, TCursor, TRawUserIdInfoKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { USER_ID_INFO_STRUCTURE_SIZE } from '../constants.js';
import { readUInt16BE } from '../utils/parserUtils.js';

type UserIdInfoRawData = Record<TRawUserIdInfoKeys, Uint8Array>;

export class UserIdInfo extends TBlob implements IUserIdInfo {
    private readonly _rawData: UserIdInfoRawData;
    public readonly structureLength: number = USER_ID_INFO_STRUCTURE_SIZE;

    private static readonly _positions: Record<TRawUserIdInfoKeys, TCursor> = {
        sizeSerialNumber: [0, 2],
        numUserIDs: [2, 4],
        sizeUserIDInfoStructure: [4, 6],
    };

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset);

        const rawDataEntries = Object.entries(UserIdInfo._positions) as [TRawUserIdInfoKeys, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as UserIdInfoRawData);
    }

    get sizeSerialNumber(): number {
        return readUInt16BE(this._rawData.sizeSerialNumber);
    }

    get numUserIDs(): number {
        return readUInt16BE(this._rawData.numUserIDs);
    }

    get sizeUserIDInfoStructure(): number {
        // This is the size of EACH User ID structure that follows. Usually 12.
        return readUInt16BE(this._rawData.sizeUserIDInfoStructure);
    }

    public toJSON() {
        return {
            sizeSerialNumber: this.sizeSerialNumber,
            numUserIDs: this.numUserIDs,
            sizeUserIDInfoStructure: this.sizeUserIDInfoStructure,
            structureLength: this.structureLength,
        };
    }
}
