
import { Buffer } from 'buffer';
import { ISignatureExpirationTime } from '../types.js';
import { TBlob } from './TBlob.js';
import { SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE } from '../constants.js';
import { bufferToHexString } from '../utils/parserUtils.js';


export class SignatureExpirationTime extends TBlob implements ISignatureExpirationTime {
    public readonly structureLength: number = SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE;
    private _expirationTimeRaw: Uint8Array;

    constructor(keyboxData: Uint8Array, blobOffset: number, expectedSize: number) {
        super(keyboxData, blobOffset); // blobOffset is the start of this specific expiration time entry

        if (expectedSize !== this.structureLength) {
            console.warn(`SignatureExpirationTime: Parent indicated structure size ${expectedSize}, but this class parses fixed ${this.structureLength} bytes.`);
        }
        this._expirationTimeRaw = this._getRelativeSubarray(0, this.structureLength);
    }

    get expirationTimeRaw(): Uint8Array {
        return this._expirationTimeRaw;
    }
    
    // Could add a getter for parsed expiration date/status if needed
    // e.g. interpret special values like 0x00000000, 0xffffffff etc.

    public toJSON() {
        return {
            expirationTimeRaw_hex: bufferToHexString(this.expirationTimeRaw),
            structureLength: this.structureLength,
        };
    }
}
