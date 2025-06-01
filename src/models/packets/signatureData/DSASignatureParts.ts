
import { Buffer } from 'buffer';
import { IDSASignatureParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI, bufferToHexString } from '../../../utils/parserUtils.js';

export class DSASignatureParts extends TBlob implements IDSASignatureParts {
    public r: Uint8Array;
    public s: Uint8Array;
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        const rResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.r = rResult.mpiValueBytes;
        currentRelativeOffset += rResult.bytesRead;

        const sResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.s = sResult.mpiValueBytes;
        currentRelativeOffset += sResult.bytesRead;
        
        this.totalLength = currentRelativeOffset;

        if (this.totalLength > dataLength) {
            console.warn(`DSASignatureParts: Parsed MPIs length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            r_hex: bufferToHexString(this.r),
            s_hex: bufferToHexString(this.s),
            totalLength: this.totalLength,
        };
    }
}
