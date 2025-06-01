
import { Buffer } from 'buffer';
import { IECDHPublicKeyParts, IKdfParameters } from '../../../types.js';
import { TBlob } from '../../TBlob.js';
import { parseMPI, parseVariableLengthField, parseKdfParameters, bufferToHexString } from '../../../utils/parserUtils.js';

export class ECDHPublicKeyParts extends TBlob implements IECDHPublicKeyParts {
    public oid: Uint8Array;
    public point: Uint8Array; // MPI of EC Point
    public kdfParameters: IKdfParameters;
    public readonly totalLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        const oidResult = parseVariableLengthField(this._kbx, this._blobOffset + currentRelativeOffset);
        this.oid = oidResult.data;
        currentRelativeOffset += oidResult.bytesRead;

        const pointResult = parseMPI(this._kbx, this._blobOffset + currentRelativeOffset);
        this.point = pointResult.mpiValueBytes; // Storing the value part of MPI
        currentRelativeOffset += pointResult.bytesRead;
        
        const kdfResult = parseKdfParameters(this._kbx, this._blobOffset + currentRelativeOffset);
        this.kdfParameters = {
            hashAlgorithmId: kdfResult.hashAlgorithmId,
            symmetricAlgorithmId: kdfResult.symmetricAlgorithmId,
        };
        currentRelativeOffset += kdfResult.bytesRead;
        
        this.totalLength = currentRelativeOffset;

        if (this.totalLength > dataLength) {
            console.warn(`ECDHPublicKeyParts: Parsed data length (${this.totalLength}) exceeds provided data length (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            oid_hex: bufferToHexString(this.oid),
            point_mpi_hex: bufferToHexString(this.point),
            kdfParameters: {
                hashAlgorithmId: this.kdfParameters.hashAlgorithmId,
                symmetricAlgorithmId: this.kdfParameters.symmetricAlgorithmId,
            },
            totalLength: this.totalLength,
        };
    }
}
