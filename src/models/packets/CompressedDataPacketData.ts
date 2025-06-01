
import { Buffer } from 'buffer';
import { ICompressedDataPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { readUInt8, sliceUint8Array } from '../../utils/parserUtils.js';
import { CompressionAlgorithm as CompressionAlgorithmEnum } from '../../constants.js';


export class CompressedDataPacketData extends TBlob implements ICompressedDataPacketData {
    public compressionAlgorithm: CompressionAlgorithmEnum;
    public compressedContent: Uint8Array;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength < 1) {
            throw new Error("CompressedDataPacketData: Data length too short for algorithm ID.");
        }

        this.compressionAlgorithm = readUInt8(this._getRelativeSubarray(0, 1)) as CompressionAlgorithmEnum;
        const contentOffset = 1;
        
        this.compressedContent = sliceUint8Array(this._kbx, this._blobOffset + contentOffset, this._blobOffset + dataLength);
    }

    public toJSON() {
        return {
            compressionAlgorithm: CompressionAlgorithmEnum[this.compressionAlgorithm] || `Unknown (${this.compressionAlgorithm})`,
            compressionAlgorithmId: this.compressionAlgorithm,
            compressedContent_length: this.compressedContent.length,
            compressedContent_hex_preview: Buffer.from(this.compressedContent.slice(0, Math.min(32, this.compressedContent.length))).toString('hex') + (this.compressedContent.length > 32 ? "..." : ""),
        };
    }
}
