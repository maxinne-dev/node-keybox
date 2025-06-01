
import { describe, it, expect, vi } from 'vitest';
import { MarkerPacketData } from '../../../models/packets/MarkerPacketData.js';
import { MARKER_PACKET_CONTENT } from '../../../constants.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('MarkerPacketData', () => {
    const keyboxData = new Uint8Array(50); // Dummy buffer
    const pgpHex = Buffer.from(MARKER_PACKET_CONTENT, 'utf8').toString('hex');

    it('should parse a valid Marker packet correctly', () => {
        const markerBytes = hexToUint8Array(pgpHex);
        keyboxData.set(markerBytes, 0);
        
        const mpData = new MarkerPacketData(keyboxData, 0, markerBytes.length);
        expect(mpData.marker).toBe(MARKER_PACKET_CONTENT);
    });

    it('should warn if data length is incorrect', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const shortMarkerBytes = hexToUint8Array(pgpHex.substring(0, 2)); // "P"
        keyboxData.set(shortMarkerBytes, 0);

        new MarkerPacketData(keyboxData, 0, shortMarkerBytes.length);
        expect(consoleWarnSpy).toHaveBeenCalledWith(`MarkerPacketData: Expected data length ${MARKER_PACKET_CONTENT.length}, got ${shortMarkerBytes.length}.`);
        consoleWarnSpy.mockRestore();
    });

    it('should warn if marker content is incorrect', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const incorrectMarker = "XYZ";
        const incorrectMarkerBytes = Buffer.from(incorrectMarker, 'utf8');
        keyboxData.set(incorrectMarkerBytes, 0);

        new MarkerPacketData(keyboxData, 0, incorrectMarkerBytes.length);
        expect(consoleWarnSpy).toHaveBeenCalledWith(`MarkerPacketData: Expected content "${MARKER_PACKET_CONTENT}", got "${incorrectMarker}".`);
        consoleWarnSpy.mockRestore();
    });

    it('should produce correct JSON output', () => {
        const markerBytes = hexToUint8Array(pgpHex);
        keyboxData.set(markerBytes, 0);
        const mpData = new MarkerPacketData(keyboxData, 0, markerBytes.length);
        const json = mpData.toJSON();

        expect(json.marker).toBe(MARKER_PACKET_CONTENT);
    });

    it('should handle parsing from an offset', () => {
        const markerBytes = hexToUint8Array(pgpHex);
        const offset = 10;
        keyboxData.set(markerBytes, offset);
        
        const mpData = new MarkerPacketData(keyboxData, offset, markerBytes.length);
        expect(mpData.marker).toBe(MARKER_PACKET_CONTENT);
    });
});
