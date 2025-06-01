
import { Buffer } from 'buffer';
import { IEdDSALegacySignatureParts } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI } from '../../../utils/parserUtils.js';

// RFC 9580 Section 5.2.3.3
export class EdDSALegacySignatureParts extends TBlob implements IEdDSALegacySignatureParts {
    public r_mpi: Uint8Array; // MPI of native R
    public s_mpi: Uint8Array; // MPI of native S
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        const rResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.r_mpi = rResult.mpiValueBytes;
        currentRelativeOffset += rResult.bytesRead;

        const sResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.s_mpi = sResult.mpiValueBytes;
        currentRelativeOffset += sResult.bytesRead;
        
        this.totalLength = currentRelativeOffset;

        if (this.totalLength > dataLength) {
            console.warn(`EdDSALegacySignatureParts: Parsed MPIs length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            r_mpi_hex: Buffer.from(this.r_mpi).toString('hex'),
            s_mpi_hex: Buffer.from(this.s_mpi).toString('hex'),
            totalLength: this.totalLength,
        };
    }
}
