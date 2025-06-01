
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BasePacket } from '../../../models/packets/BasePacket.js';
import { PacketTagInfo } from '../../../models/packets/PacketTagInfo.js';
// import { UserIdPacketData } from '../../../models/packets/UserIdPacketData.js'; // Mocked below
import { PacketTypeEnum, LengthTypeEnum, IPublicKeyPacketData } from '../../../types.js';
import { hexToUint8Array } from '../../test-utils.js';

// --- Start of Controllable Mock for LiteralPacketData ---
let literalPacketDataShouldThrow = false;
let literalPacketDataErrorMessage = "";
let literalPacketDataConstructorCalled = false;

vi.mock('../../../models/packets/LiteralPacketData.js', () => ({
    LiteralPacketData: class {
        constructor() {
            literalPacketDataConstructorCalled = true;
            if (literalPacketDataShouldThrow) {
                throw new Error(literalPacketDataErrorMessage);
            }
            // Normal mock behavior: does nothing
        }
        toJSON() {
            return { type: literalPacketDataShouldThrow ? 'MockedLiteralPacketDataThatThrows' : 'MockedLiteralPacketData' };
        }
    }
}));
// --- End of Controllable Mock ---

// Mock other specific packet data classes
vi.mock('../../../models/packets/PubKeyPacketData.js', () => ({
    PubKeyPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedPubKeyPacketData' }; }
    }
}));
vi.mock('../../../models/packets/UserIdPacketData.js', () => ({
    UserIdPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedUserIdPacketData' }; }
    }
}));
vi.mock('../../../models/packets/TrustPacketData.js', () => ({
    TrustPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedTrustPacketData' }; }
    }
}));
vi.mock('../../../models/packets/MarkerPacketData.js', () => ({
    MarkerPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedMarkerPacketData' }; }
    }
}));
vi.mock('../../../models/packets/CompressedDataPacketData.js', () => ({
    CompressedDataPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedCompressedDataPacketData' }; }
    }
}));
vi.mock('../../../models/packets/PaddingPacketData.js', () => ({
    PaddingPacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedPaddingPacketData' }; }
    }
}));
vi.mock('../../../models/packets/SEIPDData.js', () => ({
    SEIPDData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedSEIPDData' }; }
    }
}));
vi.mock('../../../models/packets/UserAttributePacketData.js', () => ({
    UserAttributePacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedUserAttributePacketData' }; }
    }
}));
vi.mock('../../../models/packets/SignaturePacketData.js', () => ({
    SignaturePacketData: class {
        constructor() { /* empty */ }
        toJSON() { return { type: 'MockedSignaturePacketData' }; }
    }
}));


describe('BasePacket', () => {
    beforeEach(() => {
        // Reset flags for LiteralPacketData mock before each test
        literalPacketDataShouldThrow = false;
        literalPacketDataErrorMessage = "";
        literalPacketDataConstructorCalled = false;
        vi.clearAllMocks(); // Clear spies like consoleErrorSpy
    });

    describe('New Format Lengths', () => {
        it('should parse 1-octet new format length', () => {
            // New format, PUBKEY (type 6 -> 0xC6), length 10 (0x0A)
            // Packet: C6 0A [10 bytes of data]
            const data = hexToUint8Array('c60a' + '00'.repeat(10));
            const packet = new BasePacket(data, 0);
            expect(packet.tagInfo.isNewFormat).toBe(true);
            expect(packet.tagInfo.packetType).toBe(PacketTypeEnum.PUBKEY);
            expect(packet.totalPacketLength).toBe(1 + 1 + 10); // tag + length_octet + data
            expect(packet.dataOffsetInKbx).toBe(2); // After tag and length octet
            expect((packet.packetSpecificData as any).toJSON().type).toBe('MockedPubKeyPacketData');
        });

        it('should parse 2-octet new format length', () => {
            // New format, UID (type 13 -> 0xCD), length 200
            // 1st length octet: 192 + ( (200-192) >> 8 ) = 192 + 0 = 192 (0xC0)
            // 2nd length octet: (200-192) & 0xFF = 8 (0x08)
            // Packet: CD C0 08 [200 bytes data]
            const data = hexToUint8Array('cdc008' + '00'.repeat(200));
            const packet = new BasePacket(data, 0);
            expect(packet.tagInfo.packetType).toBe(PacketTypeEnum.UID);
            expect(packet.totalPacketLength).toBe(1 + 2 + 200); // tag + 2 length_octets + data
            expect(packet.dataOffsetInKbx).toBe(3);
            expect((packet.packetSpecificData as any).toJSON().type).toBe('MockedUserIdPacketData');
        });

        it('should parse 5-octet new format length', () => {
            // New format, LIT (type 11 -> 0xCB), length 70000 (0x00011170)
            // 1st length octet: 255 (0xFF)
            // 4-octet length: 00011170
            // Packet: CB FF 00011170 [70000 bytes data]
            const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const data = hexToUint8Array('cbff00011170' + '00'.repeat(10)); // Shortened data for test speed
            const packet = new BasePacket(data, 0);
            expect(packet.tagInfo.packetType).toBe(PacketTypeEnum.LIT);
             // Total length is 1 (tag) + 5 (length field) + 10 (actual data provided) due to truncation warning
            expect(packet.totalPacketLength).toBe(1 + 5 + 10);
            expect(packet.dataOffsetInKbx).toBe(6);
            expect((packet.packetSpecificData as any).toJSON().type).toBe('MockedLiteralPacketData');
            expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('exceeds available keybox data'));
            consoleWarnSpy.mockRestore();
        });

        it('should warn for partial body length', () => {
            const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            // New format, LIT (type 11 -> 0xCB), partial length 2^(0xEF & 0x1F) = 2^15 = 32768
            // 1st length octet: 239 (0xEF)
            // Packet: CB EF [data]
            const data = hexToUint8Array('cbef' + '00'.repeat(10)); // only partial data for test
            new BasePacket(data, 0);
            expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Partial Body Length'));
            consoleWarnSpy.mockRestore();
        });
    });

    describe('Old Format Lengths', () => {
        it('should parse 1-octet old format length', () => {
            // Old format, SIG (type 2), 1-octet length (len type 0)
            // Tag: 10001000 = 0x88
            // Length: 5 (0x05)
            // Packet: 88 05 [5 bytes data]
            const data = hexToUint8Array('8805' + '00'.repeat(5));
            const packet = new BasePacket(data, 0);
            expect(packet.tagInfo.isNewFormat).toBe(false);
            expect(packet.tagInfo.packetType).toBe(PacketTypeEnum.SIG);
            expect(packet.tagInfo.lengthType).toBe(LengthTypeEnum.OneOctet);
            expect(packet.totalPacketLength).toBe(1 + 1 + 5);
            expect(packet.dataOffsetInKbx).toBe(2);
            expect((packet.packetSpecificData as any).toJSON().type).toBe('MockedSignaturePacketData');
        });

        it('should throw on old format partial/indeterminate length', () => {
            // Old format, type 0, indeterminate length (len type 3)
            // Tag: 10000011 = 0x83
            const data = hexToUint8Array('83' + '00'.repeat(5));
             expect(() => new BasePacket(data, 0)).toThrow('BasePacket: Old format Indeterminate/Partial Length (type 3) encountered.');
        });
    });
    
    it('should correctly calculate dataOffsetInKbx', () => {
        const packetBytesHex = 'c60a' + '00'.repeat(10); // New, 1-octet length, total 12 bytes
        const keyboxData = hexToUint8Array('ff'.repeat(50) + packetBytesHex + 'ee'.repeat(10));
        const packetOffsetInKeybox = 50;
        
        const packet = new BasePacket(keyboxData, packetOffsetInKeybox);
        // dataOffsetInKbx = packetOffsetInKeybox (50) + tagLen (1) + lengthFieldLen (1)
        expect(packet.dataOffsetInKbx).toBe(packetOffsetInKeybox + 1 + 1); 
    });


    it('should warn and truncate if declared data length exceeds available keybox data', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        // New format, PUBKEY (type 6 -> 0xC6), declared length 20 (0x14)
        // But only 10 bytes of data are provided after header in the whole buffer
        const data = hexToUint8Array('c614' + '00'.repeat(10)); 
        const packet = new BasePacket(data, 0);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('exceeds available keybox data'));
        expect(packet['_declaredDataLength']).toBe(10); // Truncated
        expect(packet.totalPacketLength).toBe(1 + 1 + 10); // Adjusted total length
        consoleWarnSpy.mockRestore();
    });

    it('should handle unknown packet types by storing raw data', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        // New format, UNKNOWN (type 30 -> 0xDE), length 5 (0x05)
        const rawPayload = '0102030405';
        const data = hexToUint8Array('de05' + rawPayload);
        const packet = new BasePacket(data, 0);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith('BasePacket: Unhandled packet type 30 (ID: 30). Storing raw data.');
        expect(packet.packetSpecificData).toBeInstanceOf(Uint8Array);
        expect(packet.packetSpecificData).toEqual(hexToUint8Array(rawPayload));
        consoleWarnSpy.mockRestore();
    });
    
    it('should catch errors during specific packet data parsing and store raw data', () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        
        literalPacketDataShouldThrow = true;
        literalPacketDataErrorMessage = "Mocked Literal Parse Error For This Test";

        const rawPayload = '0102030405';
        const data = hexToUint8Array('cb05' + rawPayload); // LIT packet, type 11. dataOffsetInKbx will be 1(tag)+1(len)=2
        const packet = new BasePacket(data, 0);

        expect(literalPacketDataConstructorCalled).toBe(true);
        expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Error parsing specific data for packet type LIT (ID: 11) at offset 2: Mocked Literal Parse Error For This Test')
        );
        expect(packet.packetSpecificData).toBeInstanceOf(Uint8Array);
        expect(packet.packetSpecificData).toEqual(hexToUint8Array(rawPayload));
        
        consoleErrorSpy.mockRestore();
        // Reset flags (already in beforeEach, but good for clarity if this test was isolated)
        literalPacketDataShouldThrow = false;
        literalPacketDataErrorMessage = "";
    });
});
