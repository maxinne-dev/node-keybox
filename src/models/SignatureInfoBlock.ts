
import { Buffer } from 'buffer';
import { ISignatureInfoBlock, TCursor, TRawSignatureInfoBlockKeys } from '../types.js';
import { TBlob } from './TBlob.js';
import { SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE } from '../constants.js';
import { readUInt16BE } from '../utils/parserUtils.js';

type SignatureInfoBlockRawData = Record<TRawSignatureInfoBlockKeys, Uint8Array>;

export class SignatureInfoBlock extends TBlob implements ISignatureInfoBlock {
    private readonly _rawData: SignatureInfoBlockRawData;
    public readonly structureLength: number = SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE;

    private static readonly _positions: Record<TRawSignatureInfoBlockKeys, TCursor> = {
        numSignatures: [0, 2],
        sizeSignatureInfoStructure: [2, 4],
    };

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset);

        const rawDataEntries = Object.entries(SignatureInfoBlock._positions) as [TRawSignatureInfoBlockKeys, TCursor][];
        this._rawData = rawDataEntries.reduce((acc, [key, [start, end]]) => {
            acc[key] = this._getRelativeSubarray(start, end);
            return acc;
        }, {} as SignatureInfoBlockRawData);
    }

    get numSignatures(): number {
        return readUInt16BE(this._rawData.numSignatures);
    }

    get sizeSignatureInfoStructure(): number {
        // Size of EACH signature information structure (usually 4 bytes for expiration time)
        return readUInt16BE(this._rawData.sizeSignatureInfoStructure);
    }

    public toJSON() {
        return {
            numSignatures: this.numSignatures,
            sizeSignatureInfoStructure: this.sizeSignatureInfoStructure,
            structureLength: this.structureLength,
        };
    }
}
