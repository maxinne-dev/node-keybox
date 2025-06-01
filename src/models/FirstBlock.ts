
import { Buffer } from 'buffer';
import { IFirstBlock, TCursor, TRawFirstBlockKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { FIRST_BLOB_STRUCTURE_SIZE, FIRST_BLOB_MAGIC, BLOB_TYPE_FIRST, FIRST_BLOB_VERSION } from '../constants.js';
import { readUInt32BE, readUInt16BE, readUInt8, bufferToString, bufferToHexString } from '../utils/parserUtils.js';

type FirstBlockRawData = {
    rawBlobLength: Uint8Array;
    blobType: Uint8Array;
    blobVersion: Uint8Array;
    headerFlags: Uint8Array;
    magic: Uint8Array;
    rawCreatedAt: Uint8Array;
    rawMaintainedAt: Uint8Array;
};

export class FirstBlock extends TBlob implements IFirstBlock {
    private readonly _rawData: FirstBlockRawData;

    public readonly structureLength: number = FIRST_BLOB_STRUCTURE_SIZE;

    private static readonly _positions: Record<keyof FirstBlockRawData, TCursor> = {
        rawBlobLength: [0, 4],
        blobType: [4, 5],
        blobVersion: [5, 6],
        headerFlags: [6, 8],
        magic: [8, 12],
        // RFU: [12, 16]
        rawCreatedAt: [16, 20],
        rawMaintainedAt: [20, 24],
        // RFU: [24, 28]
        // RFU: [28, 32]
    };

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset);

        const rawDataEntries = Object.entries(FirstBlock._positions) as [keyof FirstBlockRawData, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as FirstBlockRawData);

        if (this.blobType !== BLOB_TYPE_FIRST) {
            console.warn(`FirstBlock: Expected blob type ${BLOB_TYPE_FIRST}, got ${this.blobType}`);
        }
        if (this.blobVersion !== FIRST_BLOB_VERSION) {
            console.warn(`FirstBlock: Expected blob version ${FIRST_BLOB_VERSION}, got ${this.blobVersion}`);
        }
        if (this.magic !== FIRST_BLOB_MAGIC) {
            console.warn(`FirstBlock: Expected magic '${FIRST_BLOB_MAGIC}', got '${this.magic}'`);
        }
        if (this.blobLength !== this.structureLength) {
            console.warn(`FirstBlock: Blob length field (${this.blobLength}) does not match expected structure size (${this.structureLength}). File might be non-standard.`);
        }
    }

    get blobLength(): number {
        return readUInt32BE(this._rawData.rawBlobLength);
    }

    get blobType(): number {
        return readUInt8(this._rawData.blobType);
    }

    get blobVersion(): number {
        return readUInt8(this._rawData.blobVersion);
    }

    get headerFlags(): number {
        return readUInt16BE(this._rawData.headerFlags);
    }

    get magic(): string {
        return bufferToString(this._rawData.magic, 'utf8');
    }

    get createdAtTimestamp(): number {
        return readUInt32BE(this._rawData.rawCreatedAt);
    }

    get maintainedAtTimestamp(): number {
        return readUInt32BE(this._rawData.rawMaintainedAt);
    }

    get createdDate(): Date {
        return new Date(this.createdAtTimestamp * 1000);
    }

    get lastMaintainedDate(): Date {
        return new Date(this.maintainedAtTimestamp * 1000);
    }

    public toJSON() {
        return {
            blobLength: this.blobLength,
            blobType: this.blobType,
            blobVersion: this.blobVersion,
            headerFlags: this.headerFlags,
            magic: this.magic,
            createdAtTimestamp: this.createdAtTimestamp,
            maintainedAtTimestamp: this.maintainedAtTimestamp,
            createdDate: this.createdDate.toISOString(),
            lastMaintainedDate: this.lastMaintainedDate.toISOString(),
            structureLength: this.structureLength,
        };
    }
}
