

import { describe, it, expect, vi } from 'vitest';
import { SignatureExpirationTime } from '../../models/SignatureExpirationTime.js';
import { SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';
import { Buffer } from 'buffer';

describe('SignatureExpirationTime', () => {
    const keyboxData = new Uint8Array(50); // Dummy larger buffer
    const validExpirationHex = "FFFFFFFF"; // Example: No expiration
    const validExpirationBytes = hexToUint8Array(validExpirationHex);

    it('should parse valid SignatureExpirationTime data correctly', () => {
        keyboxData.set(validExpirationBytes, 0);
        const sigExpTime = new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);

        expect(sigExpTime.expirationTimeRaw).toEqual(validExpirationBytes);
        expect(sigExpTime.structureLength).toBe(SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validExpirationBytes, 0);
        const sigExpTime = new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
        const json = sigExpTime.toJSON();

        expect(json.expirationTimeRaw_hex).toBe(validExpirationHex.toLowerCase());
        expect(json.structureLength).toBe(SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
    });

    it('should warn if expectedSize differs from fixed structureLength', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        keyboxData.set(validExpirationBytes, 0);
        
        new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE + 1);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(`SignatureExpirationTime: Parent indicated structure size ${SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE + 1}, but this class parses fixed ${SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE} bytes.`);
        consoleWarnSpy.mockRestore();
    });

    it('should handle different expiration time values', () => {
        const specificTimeHex = "61F0C800"; // A specific timestamp
        const specificTimeBytes = hexToUint8Array(specificTimeHex);
        keyboxData.set(specificTimeBytes, 0);

        const sigExpTime = new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
        expect(sigExpTime.expirationTimeRaw).toEqual(specificTimeBytes);
    });
    
    it('should handle parsing from an offset within keyboxData', () => {
        const offset = 10;
        keyboxData.set(validExpirationBytes, offset);
        const sigExpTime = new SignatureExpirationTime(keyboxData, offset, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);

        expect(sigExpTime.expirationTimeRaw).toEqual(validExpirationBytes);
    });
});