
import { Buffer } from 'buffer';
import { IUserAttributePacketData, IUserAttributeSubpacket, IImageAttributeSubpacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { UserAttributeSubpacketType as UATSubpacketTypeEnum, ImageEncodingFormat as ImgEncFormatEnum } from '../../constants.js';
import { readUInt8, readUInt16LE, sliceUint8Array, bufferToString, readUInt32BE } from '../../utils/parserUtils.js';


// --- UserAttributeSubpacket & ImageAttributeSubpacketData ---

class ImageAttributeSubpacketData extends TBlob implements IImageAttributeSubpacketData {
    public imageHeaderVersion: number;
    public imageEncodingFormat: ImgEncFormatEnum;
    public imageData: Uint8Array;
    private _headerLength: number;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx); // dataOffsetInKbx is start of image subpacket's *content* (after type)

        if (dataLength < 3) throw new Error("ImageAttributeSubpacketData: Data too short for header length and version.");

        this._headerLength = readUInt16LE(this._getRelativeSubarray(0, 2)); // 2 bytes, little-endian
        this.imageHeaderVersion = readUInt8(this._getRelativeSubarray(2, 3)); // 1 byte
        
        let currentRelativeOffset = 3; // Start after headerLength and imageHeaderVersion

        if (this.imageHeaderVersion === 1) {
            if (this._headerLength !== 16) { // As per RFC 9580, version 1 header is 16 octets
                console.warn(`ImageAttributeSubpacketData: Version 1 header length field is ${this._headerLength}, expected 16. Parsing based on field value.`);
            }
            // Ensure we don't read past the end of the subpacket's actual data based on _headerLength
            if (dataLength < this._headerLength) throw new Error(`ImageAttributeSubpacketData: Data too short (${dataLength}) for specified v1 image header length (${this._headerLength}).`);

            this.imageEncodingFormat = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1)) as ImgEncFormatEnum;
            // The rest of the v1 header (12 bytes) is reserved and should be 0.
            // We advance currentRelativeOffset to the end of the declared header.
            currentRelativeOffset = this._headerLength;
        } else {
            console.warn(`ImageAttributeSubpacketData: Unsupported image header version ${this.imageHeaderVersion}. Raw data for image might be incorrect.`);
            this.imageEncodingFormat = 0 as ImgEncFormatEnum; // Unknown, or handle as error
            // If unknown version, currentRelativeOffset should point to where image data starts.
            // For simplicity, assume header parsing stops after version if unknown.
            // A more robust parser might try to use _headerLength even for unknown versions if available.
        }
        
        if (currentRelativeOffset > dataLength) {
             throw new Error("ImageAttributeSubpacketData: Header parsing consumed more than available data length for image data.");
        }
        this.imageData = sliceUint8Array(this._kbx, this._blobOffset + currentRelativeOffset, this._blobOffset + dataLength);
    }

    toJSON() {
        return {
            imageHeaderVersion: this.imageHeaderVersion,
            headerLengthField: this._headerLength,
            imageEncodingFormat: ImgEncFormatEnum[this.imageEncodingFormat] || `Unknown (${this.imageEncodingFormat})`,
            imageEncodingFormatId: this.imageEncodingFormat,
            imageData_length: this.imageData.length,
            imageData_hex_preview: Buffer.from(this.imageData.slice(0, Math.min(16, this.imageData.length))).toString('hex') + (this.imageData.length > 16 ? "..." : ""),
        };
    }
}

class UserAttributeSubpacket extends TBlob implements IUserAttributeSubpacket {
    public subpacketLength: number; // Length of (type + rawData)
    public type: UATSubpacketTypeEnum;
    public rawData: Uint8Array;
    public parsedData?: IImageAttributeSubpacketData | Uint8Array;
    public totalSubpacketBytes: number; // Includes length field itself

    constructor(keyboxData: Uint8Array, subpacketOffsetInKbx: number, maxAvailableLength: number) {
        super(keyboxData, subpacketOffsetInKbx);

        let lengthOfLengthField = 0;
        const firstLengthOctet = readUInt8(this._getRelativeSubarray(0, 1));

        if (firstLengthOctet < 192) {
            this.subpacketLength = firstLengthOctet;
            lengthOfLengthField = 1;
        } else if (firstLengthOctet >= 192 && firstLengthOctet < 255) {
            if (maxAvailableLength < 2) throw new Error("UserAttributeSubpacket: Not enough data for 2-octet length.");
            this.subpacketLength = ((firstLengthOctet - 192) << 8) + readUInt8(this._getRelativeSubarray(1, 2)) + 192;
            lengthOfLengthField = 2;
        } else if (firstLengthOctet === 255) {
            if (maxAvailableLength < 5) throw new Error("UserAttributeSubpacket: Not enough data for 5-octet length.");
            this.subpacketLength = readUInt32BE(this._getRelativeSubarray(1, 5));
            lengthOfLengthField = 5;
        } else {
            throw new Error(`UserAttributeSubpacket: Invalid first length octet ${firstLengthOctet}`);
        }
        
        this.totalSubpacketBytes = lengthOfLengthField + this.subpacketLength;
        if (this.totalSubpacketBytes > maxAvailableLength) {
            throw new Error(`UserAttributeSubpacket: Declared length ${this.totalSubpacketBytes} (field ${lengthOfLengthField} + data ${this.subpacketLength}) exceeds available data ${maxAvailableLength}.`);
        }

        const subpacketContentOffset = lengthOfLengthField;
        if (this.subpacketLength < 1) throw new Error("UserAttributeSubpacket: Subpacket content length is zero, too short for type.");
        
        this.type = readUInt8(this._getRelativeSubarray(subpacketContentOffset, subpacketContentOffset + 1)) as UATSubpacketTypeEnum;
        
        const subpacketRawDataOffset = subpacketContentOffset + 1;
        const subpacketRawDataLength = this.subpacketLength - 1; // -1 for the type octet
        this.rawData = sliceUint8Array(this._kbx, this._blobOffset + subpacketRawDataOffset, this._blobOffset + subpacketRawDataOffset + subpacketRawDataLength);

        if (this.type === UATSubpacketTypeEnum.IMAGE) {
            try {
                // Pass the raw data part of the subpacket to ImageAttributeSubpacketData
                this.parsedData = new ImageAttributeSubpacketData(this.rawData, 0, subpacketRawDataLength);
            } catch (e: any) {
                console.error(`Error parsing ImageAttributeSubpacketData: ${e.message}`);
                this.parsedData = this.rawData; // Fallback to raw
            }
        } else {
            this.parsedData = this.rawData; // Store raw for unhandled types
        }
    }
    
    toJSON() {
        let parsedDataJSON;
        if (this.parsedData instanceof Uint8Array) {
            parsedDataJSON = `Raw Data (${this.parsedData.length} bytes): ${Buffer.from(this.parsedData.slice(0, Math.min(16, this.parsedData.length))).toString('hex')}...`;
        } else if (typeof (this.parsedData as any)?.toJSON === 'function') {
            parsedDataJSON = (this.parsedData as any).toJSON();
        } else {
            parsedDataJSON = this.parsedData;
        }

        return {
            subpacketLengthOfTypeAndData: this.subpacketLength,
            totalSubpacketBytesIncludingLengthField: this.totalSubpacketBytes,
            type: UATSubpacketTypeEnum[this.type] || `Unknown (${this.type})`,
            typeId: this.type,
            parsedData: parsedDataJSON,
        };
    }
}


export class UserAttributePacketData extends TBlob implements IUserAttributePacketData {
    public subpackets: UserAttributeSubpacket[] = [];

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;
        while (currentRelativeOffset < dataLength) {
            const subpacket = new UserAttributeSubpacket(this._kbx, this._blobOffset + currentRelativeOffset, dataLength - currentRelativeOffset);
            this.subpackets.push(subpacket);
            currentRelativeOffset += subpacket.totalSubpacketBytes;
        }

        if (currentRelativeOffset !== dataLength) {
            console.warn(`UserAttributePacketData: Parsed subpackets total length (${currentRelativeOffset}) does not match declared data length for packet content (${dataLength}).`);
        }
    }

    public toJSON() {
        return {
            subpackets: this.subpackets.map(sp => sp.toJSON()),
        };
    }
}