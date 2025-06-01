
import { describe, it, expect } from 'vitest';
import { SignatureInfoBlock } from '../../models/SignatureInfoBlock.js';
import { SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('SignatureInfoBlock', () => {
    const validDataHex = 
        '0005' + // numSignatures (5)
        '0004';  // sizeSignatureInfoStructure (4 bytes, typical for expiration time)
    const validDataBytes = hexToUint8Array(validDataHex);
    const keyboxData = new Uint8Array(50); // Dummy larger buffer

    it('should parse valid SignatureInfoBlock data correctly', () => {
        keyboxData.set(validDataBytes, 0);
        const sigInfoBlock = new SignatureInfoBlock(keyboxData, 0);

        expect(sigInfoBlock.numSignatures).toBe(5);
        expect(sigInfoBlock.sizeSignatureInfoStructure).toBe(4);
        expect(sigInfoBlock.structureLength).toBe(SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validDataBytes, 0);
        const sigInfoBlock = new SignatureInfoBlock(keyboxData, 0);
        const json = sigInfoBlock.toJSON();

        expect(json.numSignatures).toBe(5);
        expect(json.sizeSignatureInfoStructure).toBe(4);
        expect(json.structureLength).toBe(SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE);
    });

    it('should handle zero signatures', () => {
        const zeroSigDataHex = '0000' + '0004';
        const zeroSigDataBytes = hexToUint8Array(zeroSigDataHex);
        keyboxData.set(zeroSigDataBytes, 0);
        const sigInfoBlock = new SignatureInfoBlock(keyboxData, 0);

        expect(sigInfoBlock.numSignatures).toBe(0);
    });
    
    it('should handle parsing from an offset within keyboxData', () => {
        const offset = 5;
        keyboxData.set(validDataBytes, offset);
        const sigInfoBlock = new SignatureInfoBlock(keyboxData, offset);

        expect(sigInfoBlock.numSignatures).toBe(5);
    });
});
