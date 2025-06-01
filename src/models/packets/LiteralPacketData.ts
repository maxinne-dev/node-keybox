
import { Buffer } from 'buffer';
import { ILiteralPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { LiteralDataFormat, LITERAL_FORMAT_BINARY_OCTET, LITERAL_FORMAT_TEXT_OCTET, LITERAL_FORMAT_UTF8_OCTET } from '../../constants.js';
import { readUInt8, readUInt32BE, bufferToString, sliceUint8Array } from '../../utils/parserUtils.js';

export class LiteralPacketData extends TBlob implements ILiteralPacketData {
    public format: LiteralDataFormat;
    public filename: string;
    public timestamp: number;
    public date: Date;
    public literalContent: Uint8Array;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        if (dataLength < 1 + 1 + 4) { // Min: format (1) + filename_len (1) + timestamp (4)
            throw new Error("LiteralPacketData: Data length too short for minimal header.");
        }

        const formatOctet = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
        currentRelativeOffset += 1;
        switch(formatOctet) {
            case LITERAL_FORMAT_BINARY_OCTET: this.format = LiteralDataFormat.BINARY; break;
            case LITERAL_FORMAT_TEXT_OCTET: this.format = LiteralDataFormat.TEXT; break;
            case LITERAL_FORMAT_UTF8_OCTET: this.format = LiteralDataFormat.UTF8; break;
            default:
                console.warn(`LiteralPacketData: Unknown format octet ${formatOctet}. Assuming binary.`);
                this.format = LiteralDataFormat.BINARY; // Default or throw error
        }


        const filenameLength = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
        currentRelativeOffset += 1;

        if (currentRelativeOffset + filenameLength + 4 > dataLength) {
            throw new Error("LiteralPacketData: Header fields (filename, timestamp) exceed packet data length.");
        }

        this.filename = bufferToString(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + filenameLength), 'utf8');
        currentRelativeOffset += filenameLength;

        this.timestamp = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
        this.date = new Date(this.timestamp * 1000);
        currentRelativeOffset += 4;
        
        this.literalContent = sliceUint8Array(this._kbx, this._blobOffset + currentRelativeOffset, this._blobOffset + dataLength);
    }

    public toJSON() {
        return {
            format: this.format,
            filename: this.filename,
            timestamp: this.timestamp,
            date: this.date.toISOString(),
            literalContent_hex_preview: Buffer.from(this.literalContent.slice(0, Math.min(32, this.literalContent.length))).toString('hex') + (this.literalContent.length > 32 ? "..." : ""),
            literalContent_length: this.literalContent.length,
        };
    }
}
