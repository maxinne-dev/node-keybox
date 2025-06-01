
import { describe, it, expect } from 'vitest';
import { CompressedDataPacketData } from '../../../models/packets/CompressedDataPacketData.js';
import { CompressionAlgorithm } from '../../../constants.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('CompressedDataPacketData', () => {
    const keyboxData = new Uint8Array(100); // Dummy buffer

    it('should parse ZLIB compressed data packet correctly', () => {
        const algoId = CompressionAlgorithm.ZLIB; // 2
        const compressedContentHex = "0102030405060708";
        const packetDataHex = algoId.toString(16).padStart(2, '0') + compressedContentHex;
        const packetDataBytes = hexToUint8Array(packetDataHex);

        keyboxData.set(packetDataBytes, 0);
        const cdData = new CompressedDataPacketData(keyboxData, 0, packetDataBytes.length);

        expect(cdData.compressionAlgorithm).toBe(algoId);
        expect(cdData.compressedContent).toEqual(hexToUint8Array(compressedContentHex));
    });

    it('should parse UNCOMPRESSED "compressed" data packet correctly', () => {
        const algoId = CompressionAlgorithm.UNCOMPRESSED; // 0
        const contentHex = "aabbccddeeff";
        const packetDataHex = algoId.toString(16).padStart(2, '0') + contentHex;
        const packetDataBytes = hexToUint8Array(packetDataHex);

        keyboxData.set(packetDataBytes, 0);
        const cdData = new CompressedDataPacketData(keyboxData, 0, packetDataBytes.length);

        expect(cdData.compressionAlgorithm).toBe(algoId);
        expect(cdData.compressedContent).toEqual(hexToUint8Array(contentHex));
    });
    
    it('should handle empty compressed content', () => {
        const algoId = CompressionAlgorithm.ZIP; // 1
        const packetDataHex = algoId.toString(16).padStart(2, '0'); // No content
        const packetDataBytes = hexToUint8Array(packetDataHex);

        keyboxData.set(packetDataBytes, 0);
        const cdData = new CompressedDataPacketData(keyboxData, 0, packetDataBytes.length);

        expect(cdData.compressionAlgorithm).toBe(algoId);
        expect(cdData.compressedContent.length).toBe(0);
    });

    it('should throw if data length is too short for algorithm ID', () => {
        const packetDataBytes = new Uint8Array(0); // Empty data
        expect(() => new CompressedDataPacketData(keyboxData, 0, packetDataBytes.length))
            .toThrow('CompressedDataPacketData: Data length too short for algorithm ID.');
    });

    it('should produce correct JSON output', () => {
        const algoId = CompressionAlgorithm.BZIP2; // 3
        const contentHex = "00".repeat(40); // Long content for preview check
        const packetDataHex = algoId.toString(16).padStart(2, '0') + contentHex;
        const packetDataBytes = hexToUint8Array(packetDataHex);

        keyboxData.set(packetDataBytes, 0);
        const cdData = new CompressedDataPacketData(keyboxData, 0, packetDataBytes.length);
        const json = cdData.toJSON();

        expect(json.compressionAlgorithm).toBe('BZIP2');
        expect(json.compressionAlgorithmId).toBe(algoId);
        expect(json.compressedContent_length).toBe(40);
        expect(json.compressedContent_hex_preview).toBe(contentHex.substring(0, 64) + "...");
    });
});
