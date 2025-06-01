
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { MockInstance } from 'vitest'; // Changed SpyInstance to MockInstance
import { UserAttributePacketData } from '../../../models/packets/UserAttributePacketData.js';
// UserAttributeSubpacket and ImageAttributeSubpacketData are internal to UserAttributePacketData.ts
// We will test them through the UserAttributePacketData interface.
import { UserAttributeSubpacketType, ImageEncodingFormat } from '../../../constants.js';
import { hexToUint8Array, u8 } from '../../test-utils.js';
import { Buffer } from 'buffer';
import { IImageAttributeSubpacketData } from '../../../types.js';

describe('UserAttributePacketData and its Subpackets', () => {
    const keyboxData = new Uint8Array(512); // Dummy buffer
    let consoleErrorSpy: MockInstance; // Changed SpyInstance to MockInstance

    beforeEach(() => {
        consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        consoleErrorSpy.mockRestore();
    });

    describe('UserAttributeSubpacket (via UserAttributePacketData)', () => {
        it('should parse a single IMAGE subpacket with 1-octet length', () => {
            const imageDataHex = "ABCF";
            const imageHeaderHex = "1000" + "01" + "01" + "00".repeat(12); 
            const imageSubpacketContentHex = imageHeaderHex + imageDataHex; 
            const subpacketTypeHex = "01"; 
            const subpacketLength = 1 + imageSubpacketContentHex.length / 2; 
            const subpacketHex = subpacketLength.toString(16).padStart(2, '0') + subpacketTypeHex + imageSubpacketContentHex;
            
            const packetDataBytes = hexToUint8Array(subpacketHex);
            keyboxData.set(packetDataBytes, 0);

            const uatPacket = new UserAttributePacketData(keyboxData, 0, packetDataBytes.length);
            expect(uatPacket.subpackets.length).toBe(1);
            const subpacket = uatPacket.subpackets[0];
            
            expect(subpacket.subpacketLength).toBe(subpacketLength); 
            expect(subpacket.totalSubpacketBytes).toBe(1 + subpacketLength); 
            expect(subpacket.type).toBe(UserAttributeSubpacketType.IMAGE);
            
            const imgData = subpacket.parsedData;
            expect(imgData).toBeDefined();
            if (subpacket.type === UserAttributeSubpacketType.IMAGE && imgData && !(imgData instanceof Uint8Array)) {
                expect(imgData.imageHeaderVersion).toBe(1);
                expect(imgData.imageEncodingFormat).toBe(ImageEncodingFormat.JPEG);
                expect(imgData.imageData).toEqual(hexToUint8Array(imageDataHex));
            } else {
                expect.fail("Parsed image data was not of expected type IImageAttributeSubpacketData");
            }

            const json = uatPacket.toJSON();
            const subJson = json.subpackets[0];
            expect(subJson.type).toBe('IMAGE');
            if (subJson.typeId === UserAttributeSubpacketType.IMAGE && subJson.parsedData && typeof subJson.parsedData === 'object' && 'imageEncodingFormatId' in subJson.parsedData && typeof (subJson.parsedData as any).imageEncodingFormatId === 'number' ) {
                 expect((subJson.parsedData as { imageEncodingFormat: string }).imageEncodingFormat).toBe('JPEG');
            } else {
                expect.fail("JSON parsedData for image subpacket did not have expected structure.");
            }
        });

        it('should parse a subpacket with 2-octet length', () => {
            const privateDataHex = "AA".repeat(199);
            const subpacketTypeHex = "64"; // 100
            const subpacketHex = "C008" + subpacketTypeHex + privateDataHex;
            const packetDataBytes = hexToUint8Array(subpacketHex);
            keyboxData.set(packetDataBytes, 0);

            const uatPacket = new UserAttributePacketData(keyboxData, 0, packetDataBytes.length);
            expect(uatPacket.subpackets.length).toBe(1);
            const subpacket = uatPacket.subpackets[0];
            expect(subpacket.subpacketLength).toBe(200);
            expect(subpacket.totalSubpacketBytes).toBe(2 + 200);
            expect(subpacket.type).toBe(100); // Private
            expect(subpacket.parsedData).toEqual(hexToUint8Array(privateDataHex));
        });

        it('should parse multiple subpackets, with image fallback for short data', () => {
            const subpacket1Hex = "026501"; // Len 2, Type 101 (Private), Content 1 byte (0x01)
            const imageContentHex = "ffee"; // Content for image subpacket (too short)
            const subpacket2Hex = (1 + imageContentHex.length / 2).toString(16).padStart(2, '0') + "01" + imageContentHex; // Len 3, Type IMAGE, Content 2 bytes (0xFFEE)
            const packetDataHex = subpacket1Hex + subpacket2Hex;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);

            const uatPacket = new UserAttributePacketData(keyboxData, 0, packetDataBytes.length);
            expect(uatPacket.subpackets.length).toBe(2);
            expect(uatPacket.subpackets[0].type).toBe(101);
            expect(uatPacket.subpackets[0].parsedData).toEqual(hexToUint8Array("01"));
            
            expect(uatPacket.subpackets[1].type).toBe(UserAttributeSubpacketType.IMAGE);
            // Image parsing will fail with "Data too short for header", parsedData will be raw
            expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('ImageAttributeSubpacketData: Data too short for header length and version.'));
            expect(uatPacket.subpackets[1].parsedData).toBeInstanceOf(Uint8Array);
            expect(uatPacket.subpackets[1].parsedData).toEqual(hexToUint8Array(imageContentHex));
        });
        
        it('ImageAttributeSubpacketData should handle unknown image header version', () => {
            const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const imageDataHex = "DDEE";
            const imageHeaderContentHex = "0400" + "02" + "01"; 
            const imageSubpacketContentHex = imageHeaderContentHex + imageDataHex;
            const subpacketTypeHex = "01"; 
            const subpacketHex = (1 + imageSubpacketContentHex.length / 2).toString(16).padStart(2, '0') + subpacketTypeHex + imageSubpacketContentHex;
            
            const packetDataBytes = hexToUint8Array(subpacketHex);
            keyboxData.set(packetDataBytes, 0);

            const uatPacket = new UserAttributePacketData(keyboxData, 0, packetDataBytes.length);
            const subpacket = uatPacket.subpackets[0];
            const imgData = subpacket.parsedData as IImageAttributeSubpacketData;

            expect(consoleWarnSpy).toHaveBeenCalledWith('ImageAttributeSubpacketData: Unsupported image header version 2. Raw data for image might be incorrect.');
            
            if (subpacket.type === UserAttributeSubpacketType.IMAGE && imgData && !(imgData instanceof Uint8Array)) {
                expect(imgData.imageHeaderVersion).toBe(2);
                expect(imgData.imageData).toEqual(hexToUint8Array("01" + imageDataHex));
            } else {
                 expect.fail("Parsed image data was not of expected type IImageAttributeSubpacketData for unknown version test");
            }
            consoleWarnSpy.mockRestore();
        });
    });
    
    it('should throw if subpacket length declaration exceeds available data', () => {
        const subpacketHex = "FF" + "00000100" + "01" + "00".repeat(10); // Declares 256 bytes content for type+data, 5 byte length field
                                                                    // Total declared = 5 + 256 = 261
                                                                    // Available data is 5 + 1 + 10 = 16 bytes.
        const packetDataBytes = hexToUint8Array(subpacketHex);
        keyboxData.set(packetDataBytes, 0);
        expect(() => new UserAttributePacketData(keyboxData, 0, packetDataBytes.length))
            .toThrow('UserAttributeSubpacket: Declared length 261 (field 5 + data 256) exceeds available data 16.');
    });

    it('should produce correct JSON for UserAttributePacketData with image fallback', () => {
        const imageContentHex = "AABB"; // Content for image subpacket (too short)
        const subpacketHex = (1 + imageContentHex.length / 2).toString(16).padStart(2, '0') + "01" + imageContentHex; // Len 3, Type IMAGE
        const packetDataBytes = hexToUint8Array(subpacketHex);
        keyboxData.set(packetDataBytes, 0);

        const uatPacket = new UserAttributePacketData(keyboxData, 0, packetDataBytes.length);
        const json = uatPacket.toJSON();

        expect(json.subpackets.length).toBe(1);
        expect(json.subpackets[0].type).toBe('IMAGE');
        expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('ImageAttributeSubpacketData: Data too short for header length and version.'));
        expect((json.subpackets[0].parsedData as string)).toContain(`Raw Data (${imageContentHex.length/2} bytes): ${imageContentHex.toLowerCase()}`);
    });
});
