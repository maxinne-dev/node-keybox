
import { Buffer } from 'buffer';
import { IRSASignatureParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI } from '../../../utils/parserUtils.js';

export class RSASignatureParts extends TBlob implements IRSASignatureParts {
    public signatureMPI: Uint8Array; // m^d mod n
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        const mpiResult = parseMPI(this._kbx, this._blobOffset);
        this.signatureMPI = mpiResult.mpiValueBytes;
        this.totalLength = mpiResult.bytesRead;

        if (this.totalLength > dataLength) {
            console.warn(`RSASignatureParts: Parsed MPI length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            signatureMPI_hex: Buffer.from(this.signatureMPI).toString('hex'),
            totalLength: this.totalLength,
        };
    }
}
