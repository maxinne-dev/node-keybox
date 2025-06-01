
import { Buffer } from 'buffer';
import { IKeyBlockHeader, TCursor, TRawKeyBlockHeaderKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { KEY_BLOCK_HEADER_STRUCTURE_SIZE, BLOB_TYPE_OPENPGP, BLOB_TYPE_X509 } from '../constants.js';
import { readUInt32BE, readUInt16BE, readUInt8 } from '../utils/parserUtils.js';

type KeyBlockHeaderRawData = Record<TRawKeyBlockHeaderKeys, Uint8Array>;

export class KeyBlockHeader extends TBlob implements IKeyBlockHeader {
    private readonly _rawData: KeyBlockHeaderRawData;
    public readonly structureLength: number = KEY_BLOCK_HEADER_STRUCTURE_SIZE;

    private static readonly _positions: Record<TRawKeyBlockHeaderKeys, TCursor> = {
        blobLength: [0, 4],
        type: [4, 5],
        version: [5, 6],
        blobFlags: [6, 8],
        offsetKeyblock: [8, 12],
        lengthKeyblock: [12, 16],
        numKeys: [16, 18],
        keyInfoSize: [18, 20],
    };

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset);

        const rawDataEntries = Object.entries(KeyBlockHeader._positions) as [TRawKeyBlockHeaderKeys, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as KeyBlockHeaderRawData);

        if (this.type !== BLOB_TYPE_OPENPGP && this.type !== BLOB_TYPE_X509) {
            console.warn(`KeyBlockHeader: Unexpected blob type ${this.type}. Expected ${BLOB_TYPE_OPENPGP} (OpenPGP) or ${BLOB_TYPE_X509} (X.509).`);
        }
    }

    get blobLength(): number {
        return readUInt32BE(this._rawData.blobLength);
    }

    get type(): number {
        return readUInt8(this._rawData.type);
    }

    get version(): number {
        // Version of this blob type (1 for 20-byte fingerprints, 2 for 32-byte fingerprints)
        return readUInt8(this._rawData.version);
    }

    get blobFlags(): number {
        return readUInt16BE(this._rawData.blobFlags);
    }

    get offsetKeyblock(): number {
        return readUInt32BE(this._rawData.offsetKeyblock);
    }

    get lengthKeyblock(): number {
        return readUInt32BE(this._rawData.lengthKeyblock);
    }

    get numKeys(): number {
        return readUInt16BE(this._rawData.numKeys);
    }

    get keyInfoSize(): number {
        // Size of the key information structure (e.g., 28 for v1, 56 for v2)
        return readUInt16BE(this._rawData.keyInfoSize);
    }

    public toJSON() {
        return {
            blobLength: this.blobLength,
            type: this.type,
            version: this.version,
            blobFlags: this.blobFlags,
            offsetKeyblock: this.offsetKeyblock,
            lengthKeyblock: this.lengthKeyblock,
            numKeys: this.numKeys,
            keyInfoSize: this.keyInfoSize,
            structureLength: this.structureLength,
        };
    }
}
