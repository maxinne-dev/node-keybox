
import { Buffer } from 'buffer';
import { IPacket, IPacketTagInfo, LengthTypeEnum, PacketTypeEnum } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { PacketTagInfo } from './PacketTagInfo.js';
import { readUInt8, readUInt16BE, readUInt32BE, sliceUint8Array } from '../../utils/parserUtils.js';

// Import new packet data parsers
import { PubKeyPacketData } from './PubKeyPacketData.js';
import { UserIdPacketData } from './UserIdPacketData.js';
import { TrustPacketData } from './TrustPacketData.js';
import { LiteralPacketData } from './LiteralPacketData.js';
import { MarkerPacketData } from './MarkerPacketData.js';
import { CompressedDataPacketData } from './CompressedDataPacketData.js';
import { PaddingPacketData } from './PaddingPacketData.js';
import { SEIPDData } from './SEIPDData.js';
import { UserAttributePacketData } from './UserAttributePacketData.js';
import { SignaturePacketData } from './SignaturePacketData.js';


export class BasePacket extends TBlob implements IPacket {
    public tagInfo: PacketTagInfo;
    public totalPacketLength: number;
    public dataOffsetInKbx: number;
    public packetSpecificData: IPacket['packetSpecificData'];

    private _declaredDataLength: number = 0;
    private _lengthFieldSize: number = 0;

    constructor(keyboxData: Uint8Array, packetOffsetInKbx: number) {
        super(keyboxData, packetOffsetInKbx);

        this.tagInfo = new PacketTagInfo(keyboxData, packetOffsetInKbx);

        let currentRelativeOffset = this.tagInfo.structureLength;

        if (this.tagInfo.isNewFormat) {
            const firstLengthOctet = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
            currentRelativeOffset += 1;
            this._lengthFieldSize = 1;

            if (firstLengthOctet < 192) {
                this._declaredDataLength = firstLengthOctet;
            } else if (firstLengthOctet >= 192 && firstLengthOctet <= 223) {
                if (packetOffsetInKbx + currentRelativeOffset + 1 > this._kbx.length) throw new Error("BasePacket: Not enough data for 2-octet new format length.");
                const secondLengthOctet = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
                currentRelativeOffset += 1;
                this._lengthFieldSize = 2;
                this._declaredDataLength = ((firstLengthOctet - 192) << 8) + secondLengthOctet + 192;
            } else if (firstLengthOctet === 255) {
                if (packetOffsetInKbx + currentRelativeOffset + 4 > this._kbx.length) throw new Error("BasePacket: Not enough data for 5-octet new format length.");
                this._declaredDataLength = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
                currentRelativeOffset += 4;
                this._lengthFieldSize = 5;
            } else if (firstLengthOctet >= 224 && firstLengthOctet <= 254) {
                this._declaredDataLength = 1 << (firstLengthOctet & 0x1F); // Per RFC 9580 Sec 4.2.1.4 (1st_octet & 0x1F)
                console.warn(`BasePacket: New format Partial Body Length (octet ${firstLengthOctet}). Declared length is for the first partial body: ${this._declaredDataLength}. Full streaming support not implemented.`);
            }
        } else { // Old Format
            if (this.tagInfo.lengthType === undefined) {
                 throw new Error("BasePacket: Old format packet, but lengthType is undefined.");
            }
            switch (this.tagInfo.lengthType) {
                case LengthTypeEnum.OneOctet:
                    if (packetOffsetInKbx + currentRelativeOffset + 1 > this._kbx.length) throw new Error("BasePacket: Not enough data for 1-octet old format length.");
                    this._declaredDataLength = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
                    currentRelativeOffset += 1;
                    this._lengthFieldSize = 1;
                    break;
                case LengthTypeEnum.TwoOctet:
                    if (packetOffsetInKbx + currentRelativeOffset + 2 > this._kbx.length) throw new Error("BasePacket: Not enough data for 2-octet old format length.");
                    this._declaredDataLength = readUInt16BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2));
                    currentRelativeOffset += 2;
                    this._lengthFieldSize = 2;
                    break;
                case LengthTypeEnum.FourOctet:
                    if (packetOffsetInKbx + currentRelativeOffset + 4 > this._kbx.length) throw new Error("BasePacket: Not enough data for 4-octet old format length.");
                    this._declaredDataLength = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
                    currentRelativeOffset += 4;
                    this._lengthFieldSize = 4;
                    break;
                case LengthTypeEnum.PartialBody: // Was "unknown" or "indeterminate"
                    throw new Error("BasePacket: Old format Indeterminate/Partial Length (type 3) encountered. Not supported for KeyBox packet sections.");
            }
        }
        
        this.totalPacketLength = this.tagInfo.structureLength + this._lengthFieldSize + this._declaredDataLength;
        this.dataOffsetInKbx = packetOffsetInKbx + this.tagInfo.structureLength + this._lengthFieldSize;

        // Ensure _declaredDataLength does not cause reading past the end of _kbx for packetSpecificData
        const maxAvailableDataLength = this._kbx.length - this.dataOffsetInKbx;
        if (this._declaredDataLength > maxAvailableDataLength) {
            console.warn(`BasePacket: Declared data length (${this._declaredDataLength}) for packet type ${PacketTypeEnum[this.tagInfo.packetType] || this.tagInfo.actualPacketTypeID} at offset ${this.dataOffsetInKbx} exceeds available keybox data (${maxAvailableDataLength}). Truncating to available data.`);
            this._declaredDataLength = maxAvailableDataLength;
            this.totalPacketLength = this.tagInfo.structureLength + this._lengthFieldSize + this._declaredDataLength;
        }
        
        const packetDataStartOffsetInKbx = this.dataOffsetInKbx;
        const packetDataLength = this._declaredDataLength;


        try {
            switch(this.tagInfo.packetType) {
                case PacketTypeEnum.PUBKEY:
                case PacketTypeEnum.PUBSUBKEY:
                case PacketTypeEnum.SECKEY: 
                case PacketTypeEnum.SECSUBKEY:
                    this.packetSpecificData = new PubKeyPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.UID:
                    this.packetSpecificData = new UserIdPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.TRUST:
                     this.packetSpecificData = new TrustPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.LIT:
                    this.packetSpecificData = new LiteralPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.MARKER:
                    this.packetSpecificData = new MarkerPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.COMP:
                    this.packetSpecificData = new CompressedDataPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.PADDING:
                    this.packetSpecificData = new PaddingPacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.SEIPD:
                    this.packetSpecificData = new SEIPDData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.UAT:
                    this.packetSpecificData = new UserAttributePacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                case PacketTypeEnum.SIG:
                    this.packetSpecificData = new SignaturePacketData(this._kbx, packetDataStartOffsetInKbx, packetDataLength);
                    break;
                // PKESK, SKESK, OPS, SED are not yet handled
                default:
                    console.warn(`BasePacket: Unhandled packet type ${PacketTypeEnum[this.tagInfo.packetType] || this.tagInfo.actualPacketTypeID} (ID: ${this.tagInfo.actualPacketTypeID}). Storing raw data.`);
                    this.packetSpecificData = sliceUint8Array(this._kbx, packetDataStartOffsetInKbx, packetDataStartOffsetInKbx + packetDataLength);
            }
        } catch (e: any) {
            console.error(`Error parsing specific data for packet type ${PacketTypeEnum[this.tagInfo.packetType] || this.tagInfo.actualPacketTypeID} (ID: ${this.tagInfo.actualPacketTypeID}) at offset ${packetDataStartOffsetInKbx}: ${e.message}\n${e.stack}`);
            this.packetSpecificData = sliceUint8Array(this._kbx, packetDataStartOffsetInKbx, packetDataStartOffsetInKbx + packetDataLength);
        }

        // Final check: totalPacketLength should not exceed keybox bounds from its start.
        if (packetOffsetInKbx + this.totalPacketLength > this._kbx.length) {
             // This warning is less critical if _declaredDataLength was already adjusted.
            console.warn(`BasePacket: Final calculated packet length (${this.totalPacketLength}) for packet at offset ${packetOffsetInKbx} might still exceed keybox data bounds (${this._kbx.length}). This could happen if partial lengths are used and sum up to more than available.`);
        }
    }

    public getPacketDataBytes(): Uint8Array {
         return sliceUint8Array(this._kbx, this.dataOffsetInKbx, this.dataOffsetInKbx + this._declaredDataLength);
    }

    public toJSON() {
        let specificDataJSON;
        if (this.packetSpecificData instanceof Uint8Array) {
            specificDataJSON = `Raw Data (${this.packetSpecificData.length} bytes): ${Buffer.from(this.packetSpecificData.slice(0, Math.min(32, this.packetSpecificData.length))).toString('hex')}...`;
        } else if (typeof (this.packetSpecificData as any)?.toJSON === 'function') {
            specificDataJSON = (this.packetSpecificData as any).toJSON();
        } else {
            specificDataJSON = this.packetSpecificData;
        }

        return {
            tagInfo: this.tagInfo.toJSON(),
            totalPacketLength: this.totalPacketLength,
            _declaredDataLength: this._declaredDataLength,
            _lengthFieldSize: this._lengthFieldSize,
            dataOffsetInKbx: this.dataOffsetInKbx,
            packetSpecificData: specificDataJSON,
        };
    }
}
