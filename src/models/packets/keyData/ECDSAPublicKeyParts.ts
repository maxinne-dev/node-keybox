
import { Buffer } from 'buffer';
import { IECDSAPublicKeyParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI, parseVariableLengthField, bufferToHexString } from '../../../utils/parserUtils.js';

export class ECDSAPublicKeyParts extends TBlob implements IECDSAPublicKeyParts {
    public oid: Uint8Array;
    public point: Uint8Array; // MPI of EC Point
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        const oidResult = parseVariableLengthField(this._kbx, this._blobOffset + currentRelativeOffset);
        this.oid = oidResult.data;
        currentRelativeOffset += oidResult.bytesRead;

        const pointResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.point = pointResult.mpiValueBytes; // Storing the value part of MPI for the point
        currentRelativeOffset += pointResult.bytesRead;
        
        this.totalLength = currentRelativeOffset;

        if (this.totalLength > dataLength) {
            console.warn(`ECDSAPublicKeyParts: Parsed data length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            oid_hex: bufferToHexString(this.oid),
            point_mpi_hex: bufferToHexString(this.point),
            totalLength: this.totalLength,
        };
    }
}
