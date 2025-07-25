
import { Buffer } from 'buffer';
import { IEdDSALegacyPublicKeyParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI, parseVariableLengthField, bufferToHexString } from '../../../utils/parserUtils.js';

// For EdDSALegacy keys (deprecated), Algo ID 22
// RFC 9580 Section 5.5.5.5
export class EdDSALegacyPublicKeyParts extends TBlob implements IEdDSALegacyPublicKeyParts {
    public oid: Uint8Array;
    public point: Uint8Array; // MPI of an EC point Q in prefixed native form
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
            console.warn(`EdDSALegacyPublicKeyParts: Parsed data length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            oid_hex: bufferToHexString(this.oid),
            point_mpi_hex: bufferToHexString(this.point), // Prefixed native form
            totalLength: this.totalLength,
        };
    }
}
