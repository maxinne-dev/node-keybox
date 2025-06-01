import { describe, it, expect, vi } from 'vitest';
import { PacketTagInfo } from '../../../models/packets/PacketTagInfo.js';
import { PacketTypeEnum, LengthTypeEnum } from '../../../types.js';
import { hexToUint8Array } from '../../test-utils.js';

describe('PacketTagInfo', () => {
    it('should parse a new format packet tag (Public Key Packet - Type 6)', () => {
        // Bit 7 (Marker) = 1
        // Bit 6 (Format) = 1 (New)
        // Bits 5-0 (Type) = 000110 (6 for PUBKEY)
        // 11000110 = 0xC6
        const data = hexToUint8Array('c6');
        const tagInfo = new PacketTagInfo(data, 0);

        expect(tagInfo.isValidMarker).toBe(true);
        expect(tagInfo.isNewFormat).toBe(true);
        expect(tagInfo.packetType).toBe(PacketTypeEnum.PUBKEY);
        expect(tagInfo.actualPacketTypeID).toBe(6);
        expect(tagInfo.lengthType).toBeUndefined();
        expect(tagInfo.structureLength).toBe(1);
    });

    it('should parse an old format packet tag (Signature Packet - Type 2, 1-octet length)', () => {
        // Bit 7 (Marker) = 1
        // Bit 6 (Format) = 0 (Old)
        // Bits 5-2 (Type) = 0010 (2 for SIG)
        // Bits 1-0 (Length Type) = 00 (1-octet)
        // 10001000 = 0x88
        const data = hexToUint8Array('88');
        const tagInfo = new PacketTagInfo(data, 0);

        expect(tagInfo.isValidMarker).toBe(true);
        expect(tagInfo.isNewFormat).toBe(false);
        expect(tagInfo.packetType).toBe(PacketTypeEnum.SIG);
        expect(tagInfo.actualPacketTypeID).toBe(2);
        expect(tagInfo.lengthType).toBe(LengthTypeEnum.OneOctet);
    });

    it('should parse an old format packet tag (Secret Key Packet - Type 5, 2-octet length)', () => {
        // Bit 7 (Marker) = 1
        // Bit 6 (Format) = 0 (Old)
        // Bits 5-2 (Type) = 0101 (5 for SECKEY)
        // Bits 1-0 (Length Type) = 01 (2-octet)
        // 10010101 = 0x95
        const data = hexToUint8Array('95');
        const tagInfo = new PacketTagInfo(data, 0);

        expect(tagInfo.isValidMarker).toBe(true);
        expect(tagInfo.isNewFormat).toBe(false);
        expect(tagInfo.packetType).toBe(PacketTypeEnum.SECKEY);
        expect(tagInfo.actualPacketTypeID).toBe(5);
        expect(tagInfo.lengthType).toBe(LengthTypeEnum.TwoOctet);
    });

    it('should warn if marker bit is not set', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        // Bit 7 (Marker) = 0 - Invalid
        // 01000110 = 0x46
        const data = hexToUint8Array('46');
        new PacketTagInfo(data, 0);
        expect(consoleWarnSpy).toHaveBeenCalledWith('PacketTagInfo: Packet marker bit (bit 7) is not set. This might not be a valid OpenPGP packet start.');
        consoleWarnSpy.mockRestore();
    });

    it('should produce correct JSON output for new format', () => {
        const data = hexToUint8Array('c6'); // PUBKEY
        const tagInfo = new PacketTagInfo(data, 0);
        const json = tagInfo.toJSON();
        expect(json.packetTypeEnumName).toBe('PUBKEY');
        expect(json.actualPacketTypeID).toBe(6);
        expect(json.lengthType).toBeUndefined();
    });

    it('should produce correct JSON output for old format', () => {
        const data = hexToUint8Array('88'); // SIG, 1-octet length
        const tagInfo = new PacketTagInfo(data, 0);
        const json = tagInfo.toJSON();
        expect(json.packetTypeEnumName).toBe('SIG');
        expect(json.actualPacketTypeID).toBe(2);
        expect(json.lengthType).toBe('OneOctet');
    });
});
