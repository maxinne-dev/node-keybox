
import { Buffer } from 'buffer';
import { IRSAPublicKeyParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { readUInt16BE, sliceUint8Array, bufferToHexString } from '../../../utils/parserUtils.js';

// RSA public key parts (modulus n, exponent e) are stored as MPIs.
// An MPI consists of a 2-octet length field (number of bits) followed by the number itself.
function parseMPI(keyboxData: Uint8Array, offset: number): { mpi: Uint8Array, bits: number, bytesRead: number } {
    const bitLength = readUInt16BE(keyboxData, offset);
    const byteLength = Math.ceil(bitLength / 8);
    const mpiData = sliceUint8Array(keyboxData, offset + 2, offset + 2 + byteLength);
    return { mpi: mpiData, bits: bitLength, bytesRead: 2 + byteLength };
}

export class RSAPublicKeyParts extends TBlob implements IRSAPublicKeyParts {
    public modulusN: Uint8Array;
    public publicExponentE: Uint8Array;
    public bitLengthModN: number;
    public bitLengthExpE: number;
    public readonly totalLength: number; // Total bytes read for these MPIs

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, _dataLength: number) {
        // _dataLength is the total length of the RSA key material section
        super(keyboxData, dataOffsetInKbx); // dataOffsetInKbx is where N's MPI starts

        const nPartResult = parseMPI(this._kbx, this._blobOffset);
        this.modulusN = nPartResult.mpi;
        this.bitLengthModN = nPartResult.bits;
        let currentRelativeOffset = nPartResult.bytesRead;

        const ePartResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.publicExponentE = ePartResult.mpi;
        this.bitLengthExpE = ePartResult.bits;
        currentRelativeOffset += ePartResult.bytesRead;

        this.totalLength = currentRelativeOffset;

        if (this.totalLength > _dataLength) {
            console.warn(`RSAPublicKeyParts: Parsed MPIs length (${this.totalLength}) exceeds provided data length (${_dataLength}).`);
        }
    }

    public toJSON() {
        return {
            modulusN_hex: bufferToHexString(this.modulusN),
            publicExponentE_hex: bufferToHexString(this.publicExponentE),
            bitLengthModN: this.bitLengthModN,
            bitLengthExpE: this.bitLengthExpE,
            totalLength: this.totalLength,
        };
    }
}
