
import { Buffer } from 'buffer';
import { ISignatureSubpacket } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { SignatureSubpacketType as SigSubpacketTypeEnum } from '../../constants.js';
import { readUInt8, readUInt32BE, sliceUint8Array, bufferToHexString } from '../../utils/parserUtils.js';


export class SignatureSubpacket extends TBlob implements ISignatureSubpacket {
    public subpacketLength: number; // Length of (type + rawData)
    public type: SigSubpacketTypeEnum;
    public isCritical: boolean;
    public rawData: Uint8Array;
    public totalSubpacketBytes: number; // Includes length field itself

    constructor(keyboxData: Uint8Array, subpacketOffsetInKbx: number, maxAvailableLength: number) {
        super(keyboxData, subpacketOffsetInKbx);

        let lengthOfLengthField = 0;
        const firstLengthOctet = readUInt8(this._getRelativeSubarray(0, 1));

        if (firstLengthOctet < 192) {
            this.subpacketLength = firstLengthOctet;
            lengthOfLengthField = 1;
        } else if (firstLengthOctet >= 192 && firstLengthOctet < 255) {
             if (maxAvailableLength < 2) throw new Error("SignatureSubpacket: Not enough data for 2-octet length.");
            this.subpacketLength = ((firstLengthOctet - 192) << 8) + readUInt8(this._getRelativeSubarray(1, 2)) + 192;
            lengthOfLengthField = 2;
        } else if (firstLengthOctet === 255) {
            if (maxAvailableLength < 5) throw new Error("SignatureSubpacket: Not enough data for 5-octet length.");
            this.subpacketLength = readUInt32BE(this._getRelativeSubarray(1, 5));
            lengthOfLengthField = 5;
        } else {
            throw new Error(`SignatureSubpacket: Invalid first length octet ${firstLengthOctet}`);
        }
        
        this.totalSubpacketBytes = lengthOfLengthField + this.subpacketLength;

        if (this.totalSubpacketBytes > maxAvailableLength) {
            throw new Error(`SignatureSubpacket: Declared length ${this.totalSubpacketBytes} (field ${lengthOfLengthField} + data ${this.subpacketLength}) exceeds available data ${maxAvailableLength}.`);
        }
        
        const subpacketContentOffset = lengthOfLengthField;
        if (this.subpacketLength < 1) throw new Error("SignatureSubpacket: Subpacket content length is zero, too short for type.");
        
        const typeOctet = readUInt8(this._getRelativeSubarray(subpacketContentOffset, subpacketContentOffset + 1));
        this.isCritical = (typeOctet & 0x80) !== 0;
        this.type = (typeOctet & 0x7F) as SigSubpacketTypeEnum;
        
        const subpacketRawDataOffset = subpacketContentOffset + 1;
        const subpacketRawDataLength = this.subpacketLength - 1; // -1 for the type octet
        
        this.rawData = sliceUint8Array(this._kbx, this._blobOffset + subpacketRawDataOffset, this._blobOffset + subpacketRawDataOffset + subpacketRawDataLength);
        // Specific parsing of rawData based on this.type could be added here
        // For now, we store rawData.
    }
    
    toJSON() {
        // Basic toJSON, can be expanded to parse rawData based on type
        return {
            subpacketLengthOfTypeAndData: this.subpacketLength,
            totalSubpacketBytesIncludingLengthField: this.totalSubpacketBytes,
            type: SigSubpacketTypeEnum[this.type] || `Unknown (${this.type})`,
            typeId: this.type,
            isCritical: this.isCritical,
            rawData_hex: bufferToHexString(this.rawData),
        };
    }
}
