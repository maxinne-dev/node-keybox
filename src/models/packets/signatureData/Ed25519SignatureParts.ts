
import { Buffer } from 'buffer';
import { IEd25519SignatureParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { sliceUint8Array } from '../../../utils/parserUtils.js';

// RFC 9580 Section 5.2.3.4
export class Ed25519SignatureParts extends TBlob implements IEd25519SignatureParts {
    public nativeSignature: Uint8Array; // 64 octets
    public readonly totalLength: number = 64;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength < this.totalLength) {
            throw new Error(`Ed25519SignatureParts: Data length (${dataLength}) is less than expected ${this.totalLength} bytes.`);
        }
        
        this.nativeSignature = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + this.totalLength);

        if (this.totalLength > dataLength) { // Should not happen if above check passes
            console.warn(`Ed25519SignatureParts: Expected data length ${this.totalLength}, but available data length from packet is ${dataLength}. Using ${this.totalLength}.`);
        }
    }

    public toJSON() {
        return {
            nativeSignature_hex: Buffer.from(this.nativeSignature).toString('hex'),
            totalLength: this.totalLength,
        };
    }
}
