
import { Buffer } from 'buffer';
import { IEd448PublicKeyParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { sliceUint8Array } from '../../../utils/parserUtils.js';

// RFC 9580 Section 5.5.5.10
export class Ed448PublicKeyParts extends TBlob implements IEd448PublicKeyParts {
    public publicKey: Uint8Array; // 57 octets native public key
    public readonly totalLength: number = 57;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength < this.totalLength) {
            throw new Error(`Ed448PublicKeyParts: Data length (${dataLength}) is less than expected ${this.totalLength} bytes.`);
        }

        this.publicKey = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + this.totalLength);

        if (this.totalLength > dataLength) {
             console.warn(`Ed448PublicKeyParts: Expected data length ${this.totalLength}, but available data length from packet is ${dataLength}. Using ${this.totalLength}.`);
        }
    }

    public toJSON() {
        return {
            publicKey_hex: Buffer.from(this.publicKey).toString('hex'),
            totalLength: this.totalLength,
        };
    }
}
