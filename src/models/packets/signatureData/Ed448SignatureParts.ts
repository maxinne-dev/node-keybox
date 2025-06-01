
import { Buffer } from 'buffer';
import { IEd448SignatureParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { sliceUint8Array, bufferToHexString } from '../../../utils/parserUtils.js';

// RFC 9580 Section 5.2.3.5
export class Ed448SignatureParts extends TBlob implements IEd448SignatureParts {
    public nativeSignature: Uint8Array; // 114 octets
    public readonly totalLength: number = 114;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength < this.totalLength) {
            throw new Error(`Ed448SignatureParts: Data length (${dataLength}) is less than expected ${this.totalLength} bytes.`);
        }
        
        this.nativeSignature = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + this.totalLength);
        
        if (this.totalLength > dataLength) { // Should not happen if above check passes
            console.warn(`Ed448SignatureParts: Expected data length ${this.totalLength}, but available data length from packet is ${dataLength}. Using ${this.totalLength}.`);
        }
    }

    public toJSON() {
        return {
            nativeSignature_hex: bufferToHexString(this.nativeSignature),
            totalLength: this.totalLength,
        };
    }
}
