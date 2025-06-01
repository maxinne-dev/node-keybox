
import { Buffer } from 'buffer';
import { IBlockTrailingData, TCursor, TRawBlockTrailingDataKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { BLOCK_TRAILING_DATA_STRUCTURE_SIZE } from '../constants.js';
import { readUInt32BE, readUInt8 } from '../utils/parserUtils.js';

type BlockTrailingDataRawData = Record<TRawBlockTrailingDataKeys, Uint8Array>;

export class BlockTrailingData extends TBlob implements IBlockTrailingData {
    private readonly _rawData: BlockTrailingDataRawData;
    public readonly structureLength: number = BLOCK_TRAILING_DATA_STRUCTURE_SIZE;

    private static readonly _positions: Record<TRawBlockTrailingDataKeys, TCursor> = {
        ownerTrust: [0, 1],
        allValidity: [1, 2],
        // RFU: [2, 4]
        recheckAfter: [4, 8],
        latestTimestamp: [8, 12],
        blobCreatedAtTimestamp: [12, 16],
        sizeReservedSpace: [16, 20],
    };

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset);

        const rawDataEntries = Object.entries(BlockTrailingData._positions) as [TRawBlockTrailingDataKeys, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as BlockTrailingDataRawData);
    }

    get ownerTrust(): number {
        return readUInt8(this._rawData.ownerTrust);
    }

    get allValidity(): number {
        return readUInt8(this._rawData.allValidity);
    }

    get allValidityParsed(): IBlockTrailingData['allValidityParsed'] {
        // For X.509, Bit 4 set := key has been revoked.
        // This check assumes it might be an X.509 context.
        // A more robust solution would involve knowing the parent blob type.
        return {
            keyRevoked: (this.allValidity & 0b00010000) !== 0, // Bit 4 (0x10)
        };
    }

    get recheckAfter(): number {
        return readUInt32BE(this._rawData.recheckAfter);
    }

    get latestTimestamp(): number {
        return readUInt32BE(this._rawData.latestTimestamp);
    }

    get blobCreatedAtTimestamp(): number {
        return readUInt32BE(this._rawData.blobCreatedAtTimestamp);
    }

    get blobCreatedAtDate(): Date {
        return new Date(this.blobCreatedAtTimestamp * 1000);
    }

    get sizeReservedSpace(): number {
        return readUInt32BE(this._rawData.sizeReservedSpace);
    }

    public toJSON() {
        return {
            ownerTrust: this.ownerTrust,
            allValidity: this.allValidity,
            allValidityParsed: this.allValidityParsed,
            recheckAfter: this.recheckAfter,
            latestTimestamp: this.latestTimestamp,
            blobCreatedAtTimestamp: this.blobCreatedAtTimestamp,
            blobCreatedAtDate: this.blobCreatedAtDate.toISOString(),
            sizeReservedSpace: this.sizeReservedSpace,
            structureLength: this.structureLength,
        };
    }
}
