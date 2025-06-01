import { describe, it, expect, vi } from 'vitest';
import { SignatureExpirationTime } from '../../models/SignatureExpirationTime.js';
import { SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE } from '../../constants.js';
import { hexToUint8Array } from '../test-utils.js';

describe('SignatureExpirationTime', () => {
    const keyboxData = new Uint8Array(100); // Dummy larger buffer

    const validExpirationTimeData = hexToUint8Array(
        '00000064' // expirationTimeRaw (100 in hex)
    );

    it('should parse valid SignatureExpirationTime data correctly', () => {
        keyboxData.set(validExpirationTimeData, 0);
        const sigExpTime = new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);

        expect(sigExpTime.expirationTimeRaw).toEqual(validExpirationTimeData);
        expect(sigExpTime.structureLength).toBe(SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
    });

    it('should produce correct JSON output', () => {
        keyboxData.set(validExpirationTimeData, 0);
        const sigExpTime = new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
        const json = sigExpTime.toJSON();

        expect(json.expirationTimeRaw).toBe('00000064');
        expect(json.structureLength).toBe(SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE);
    });

    it('should warn if expectedSize does not match structureLength', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        new SignatureExpirationTime(keyboxData, 0, SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE + 2); // Pass a mismatched size
        expect(consoleWarnSpy).toHaveBeenCalledWith(
            `SignatureExpirationTime: Parent indicated structure size ${SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE + 2}, but this class parses fixed ${SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE} bytes.`
        );
        consoleWarnSpy.mockRestore();
    });
});
