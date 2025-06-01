
import { IPacketTagInfo, PacketTypeEnum, LengthTypeEnum } from '../../types.js';
import { TBlob } from '../TBlob.js';
import {
    PACKET_TAG_MARKER_BIT,
    PACKET_TAG_NEW_FORMAT_BIT,
    PACKET_TAG_TYPE_MASK_NEW_FORMAT,
    PACKET_TAG_TYPE_MASK_OLD_FORMAT,
    PACKET_TAG_TYPE_SHIFT_OLD_FORMAT,
    PACKET_TAG_LENGTH_TYPE_MASK_OLD_FORMAT
} from '../../constants.js';
import { readUInt8 } from '../../utils/parserUtils.js';

export class PacketTagInfo extends TBlob implements IPacketTagInfo {
    public readonly structureLength: number = 1; // Packet tag is 1 byte

    public isValidMarker: boolean;
    public isNewFormat: boolean;
    public packetType: PacketTypeEnum; // Interpreted type based on format
    public actualPacketTypeID: number; // Raw numeric ID
    public lengthType?: LengthTypeEnum; // Only for old format

    constructor(keyboxData: Uint8Array, blobOffset: number) {
        super(keyboxData, blobOffset); // blobOffset is the start of the packet tag byte

        const tagByte = readUInt8(this._getRelativeSubarray(0, 1));

        this.isValidMarker = (tagByte & PACKET_TAG_MARKER_BIT) !== 0;
        if (!this.isValidMarker) {
            // As per RFC 4880, bit 7 MUST be 1.
            // However, GnuPG spec for Keybox seems more lenient or implies context.
            // For strict OpenPGP, this would be an invalid packet.
            console.warn("PacketTagInfo: Packet marker bit (bit 7) is not set. This might not be a valid OpenPGP packet start.");
        }
        
        this.isNewFormat = (tagByte & PACKET_TAG_NEW_FORMAT_BIT) !== 0;

        if (this.isNewFormat) {
            // New Format (RFC 4880 Section 4.2)
            // Bits 5-0 define the packet type (tag).
            this.actualPacketTypeID = tagByte & PACKET_TAG_TYPE_MASK_NEW_FORMAT;
            this.packetType = this.actualPacketTypeID as PacketTypeEnum; // Direct cast, assumes enum covers all new IDs
            // Length is determined by subsequent octets, not in this tag byte. LengthTypeEnum is not used.
        } else {
            // Old Format (RFC 4880 Section 4.2)
            // Bits 5-2 define the packet type (tag).
            this.actualPacketTypeID = (tagByte & PACKET_TAG_TYPE_MASK_OLD_FORMAT) >> PACKET_TAG_TYPE_SHIFT_OLD_FORMAT;
            this.packetType = this.actualPacketTypeID as PacketTypeEnum; // Direct cast
            // Bits 1-0 define the length-type.
            this.lengthType = (tagByte & PACKET_TAG_LENGTH_TYPE_MASK_OLD_FORMAT) as LengthTypeEnum;
        }
    }

    public toJSON() {
        return {
            isValidMarker: this.isValidMarker,
            isNewFormat: this.isNewFormat,
            packetTypeEnumName: PacketTypeEnum[this.packetType] || "Unknown/Reserved",
            actualPacketTypeID: this.actualPacketTypeID,
            lengthType: this.lengthType !== undefined ? LengthTypeEnum[this.lengthType] : undefined,
            structureLength: this.structureLength,
        };
    }
}
