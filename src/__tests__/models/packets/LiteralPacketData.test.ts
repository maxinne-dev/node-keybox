import { describe, it, expect, vi } from 'vitest';
import { LiteralPacketData } from '../../../models/packets/LiteralPacketData.js';
import { LiteralDataFormat } from '../../../constants.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('LiteralPacketData', () => {
    const keyboxData = new Uint8Array(256); // Dummy buffer
    const testTimestamp = Math.floor(new Date('2023-02-15T10:20:30Z').getTime() / 1000);
    const testTimestampHex = testTimestamp.toString(16).padStart(8, '0');

    it('should parse a binary literal data packet correctly', () => {
        const filename = "file.bin";
        const content = "binary data content";
        const filenameBytes = Buffer.from(filename, 'utf8');
        const contentBytes = Buffer.from(content, 'utf8');
        const contentUint8Array = Uint8Array.from(contentBytes);


        const packetDataHex = 
            '62' + // 'b' for binary
            filenameBytes.length.toString(16).padStart(2, '0') + 
            Buffer.from(filenameBytes).toString('hex') +
            testTimestampHex +
            Buffer.from(contentBytes).toString('hex');
        const packetDataBytes = hexToUint8Array(packetDataHex);
        
        keyboxData.set(packetDataBytes, 0);
        const litData = new LiteralPacketData(keyboxData, 0, packetDataBytes.length);

        expect(litData.format).toBe(LiteralDataFormat.BINARY);
        expect(litData.filename).toBe(filename);
        expect(litData.timestamp).toBe(testTimestamp);
        expect(litData.date).toEqual(new Date(testTimestamp * 1000));
        expect(litData.literalContent).toEqual(contentUint8Array);
    });

    it('should parse a text literal data packet (format "t")', () => {
        const packetDataHex = '7400' + testTimestampHex + '74657874'; // 't', empty filename, time, "text"
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        const litData = new LiteralPacketData(keyboxData, 0, packetDataBytes.length);
        expect(litData.format).toBe(LiteralDataFormat.TEXT);
    });
    
    it('should parse a UTF-8 literal data packet (format "u")', () => {
        const packetDataHex = '7500' + testTimestampHex + '75746638'; // 'u', empty filename, time, "utf8"
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        const litData = new LiteralPacketData(keyboxData, 0, packetDataBytes.length);
        expect(litData.format).toBe(LiteralDataFormat.UTF8);
    });

    it('should warn and default to binary for unknown format octet', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const packetDataHex = 'FF00' + testTimestampHex + '64617461'; // Unknown format FF
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        
        const litData = new LiteralPacketData(keyboxData, 0, packetDataBytes.length);
        expect(consoleWarnSpy).toHaveBeenCalledWith('LiteralPacketData: Unknown format octet 255. Assuming binary.');
        expect(litData.format).toBe(LiteralDataFormat.BINARY);
        consoleWarnSpy.mockRestore();
    });

    it('should throw if data length is too short for minimal header', () => {
        const packetDataBytes = hexToUint8Array('6204file'); // format, filename_len, filename (too short for timestamp)
        keyboxData.set(packetDataBytes, 0);
        expect(() => new LiteralPacketData(keyboxData, 0, packetDataBytes.length))
            .toThrow('LiteralPacketData: Data length too short for minimal header.');
    });
    
    it('should throw if data length is too short for filename and timestamp', () => {
        const filename = "verylongfilename";
        const filenameBytes = Buffer.from(filename, 'utf8');
        const packetDataHex = 
            '62' + 
            filenameBytes.length.toString(16).padStart(2, '0') + 
            Buffer.from(filenameBytes).toString('hex') + // No space for timestamp
            '1234'; // Not enough for 4-byte timestamp
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);

        expect(() => new LiteralPacketData(keyboxData, 0, packetDataBytes.length))
            .toThrow('LiteralPacketData: Header fields (filename, timestamp) exceed packet data length.');
    });

    it('should produce correct JSON output', () => {
        const contentHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"; // 33 bytes
        const packetDataHex = `6200${testTimestampHex}${contentHex}`; // binary, no filename
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        const litData = new LiteralPacketData(keyboxData, 0, packetDataBytes.length);
        const json = litData.toJSON();

        expect(json.format).toBe(LiteralDataFormat.BINARY);
        expect(json.filename).toBe("");
        expect(json.date).toBe(new Date(testTimestamp * 1000).toISOString());
        expect(json.literalContent_hex_preview).toBe(contentHex.substring(0, 64).toLowerCase() + "..."); // 32 bytes * 2 hex chars
        expect(json.literalContent_length).toBe(33);
    });
});