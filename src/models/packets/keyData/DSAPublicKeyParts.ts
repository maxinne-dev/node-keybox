
import { Buffer } from 'buffer';
import { IDSAPublicKeyParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI } from '../../../utils/parserUtils.js';

export class DSAPublicKeyParts extends TBlob implements IDSAPublicKeyParts {
    public primeP: Uint8Array;
    public groupOrderQ: Uint8Array;
    public groupGeneratorG: Uint8Array;
    public publicKeyY: Uint8Array;
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        const pResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.primeP = pResult.mpiValueBytes;
        currentRelativeOffset += pResult.bytesRead;

        const qResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.groupOrderQ = qResult.mpiValueBytes;
        currentRelativeOffset += qResult.bytesRead;

        const gResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.groupGeneratorG = gResult.mpiValueBytes;
        currentRelativeOffset += gResult.bytesRead;

        const yResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.publicKeyY = yResult.mpiValueBytes;
        currentRelativeOffset += yResult.bytesRead;
        
        this.totalLength = currentRelativeOffset;

        if (this.totalLength > dataLength) {
            console.warn(`DSAPublicKeyParts: Parsed MPIs length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            primeP_hex: Buffer.from(this.primeP).toString('hex'),
            groupOrderQ_hex: Buffer.from(this.groupOrderQ).toString('hex'),
            groupGeneratorG_hex: Buffer.from(this.groupGeneratorG).toString('hex'),
            publicKeyY_hex: Buffer.from(this.publicKeyY).toString('hex'),
            totalLength: this.totalLength,
        };
    }
}
