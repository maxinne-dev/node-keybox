import { describe, it, expect } from 'vitest';
import { PaddingPacketData } from '../../../models/packets/PaddingPacketData.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('PaddingPacketData', () => {
    const keyboxData = new Uint8Array(100); // Dummy buffer

    it('should store padding content correctly', () => {
        const paddingHex = "0102030405060708090a101112131415"; // 16 bytes of padding
        const paddingBytes = hexToUint8Array(paddingHex);
        
        keyboxData.set(paddingBytes, 5); // Store at an offset
        const padData = new PaddingPacketData(keyboxData, 5, paddingBytes.length);

        expect(padData.paddingContent).toEqual(paddingBytes);
    });

    it('should handle empty padding content', () => {
        const paddingBytes = new Uint8Array(0);
        
        const padData = new PaddingPacketData(keyboxData, 0, paddingBytes.length);

        expect(padData.paddingContent).toEqual(paddingBytes);
        expect(padData.paddingContent.length).toBe(0);
    });

    it('should produce correct JSON output with preview', () => {
        const longPaddingHex = "AB".repeat(40); // 40 bytes, preview will be 32 bytes (64 hex chars) + "..."
        const paddingBytes = hexToUint8Array(longPaddingHex);
        
        keyboxData.set(paddingBytes, 0);
        const padData = new PaddingPacketData(keyboxData, 0, paddingBytes.length);
        const json = padData.toJSON();

        expect(json.paddingContent_length).toBe(40);
        expect(json.paddingContent_hex_preview).toBe(longPaddingHex.substring(0, 64).toLowerCase() + "...");
    });

    it('should produce correct JSON output for short content without ellipsis', () => {
        const shortPaddingHex = "CD".repeat(10); // 10 bytes
        const paddingBytes = hexToUint8Array(shortPaddingHex);
        
        keyboxData.set(paddingBytes, 0);
        const padData = new PaddingPacketData(keyboxData, 0, paddingBytes.length);
        const json = padData.toJSON();

        expect(json.paddingContent_length).toBe(10);
        expect(json.paddingContent_hex_preview).toBe(shortPaddingHex.toLowerCase());
    });
});