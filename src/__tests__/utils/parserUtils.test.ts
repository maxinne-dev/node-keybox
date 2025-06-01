import { describe, it, expect, vi } from 'vitest';
import {
    readUInt8,
    readUInt16BE,
    readUInt16LE,
    readUInt32BE,
    bufferToString,
    sliceUint8Array,
    parseMPI,
    parseVariableLengthField,
    parseKdfParameters
} from '../../utils/parserUtils.js';
import { hexToUint8Array } from '../test-utils.js';

describe('parserUtils', () => {
    describe('readUInt8', () => {
        it('should read a UInt8 value', () => {
            const buffer = hexToUint8Array('ab');
            expect(readUInt8(buffer)).toBe(0xab);
        });
        it('should read a UInt8 value with offset', () => {
            const buffer = hexToUint8Array('00ab');
            expect(readUInt8(buffer, 1)).toBe(0xab);
        });
    });

    describe('readUInt16BE', () => {
        it('should read a UInt16BE value', () => {
            const buffer = hexToUint8Array('abcd');
            expect(readUInt16BE(buffer)).toBe(0xabcd);
        });
    });

    describe('readUInt16LE', () => {
        it('should read a UInt16LE value', () => {
            const buffer = hexToUint8Array('cdab');
            expect(readUInt16LE(buffer)).toBe(0xabcd);
        });
    });

    describe('readUInt32BE', () => {
        it('should read a UInt32BE value', () => {
            const buffer = hexToUint8Array('abcdef12');
            expect(readUInt32BE(buffer)).toBe(0xabcdef12);
        });
    });

    describe('bufferToString', () => {
        it('should convert buffer to utf8 string', () => {
            const buffer = hexToUint8Array('48656c6c6f'); // "Hello"
            expect(bufferToString(buffer)).toBe('Hello');
        });
    });

    describe('sliceUint8Array', () => {
        it('should slice a Uint8Array', () => {
            const buffer = hexToUint8Array('0011223344');
            const sliced = sliceUint8Array(buffer, 1, 3);
            expect(sliced).toEqual(hexToUint8Array('1122'));
        });
    });

    describe('parseMPI', () => {
        it('should parse a valid MPI', () => {
            // Example: MPI for value 511 (0x01FF), bit length 9
            // Length: 0x0009 (9 bits)
            // Value: 0x01FF
            const mpiData = hexToUint8Array('000901ff');
            const result = parseMPI(mpiData, 0);
            expect(result.bitLength).toBe(9);
            expect(result.mpiValueBytes).toEqual(hexToUint8Array('01ff'));
            expect(result.bytesRead).toBe(4); // 2 for length, 2 for value
            expect(result.mpi).toEqual(mpiData);
        });

        it('should throw if buffer too short for length', () => {
            const shortData = hexToUint8Array('00');
            expect(() => parseMPI(shortData, 0)).toThrow('Buffer too short to read MPI bit length.');
        });

        it('should throw if buffer too short for data', () => {
            const shortData = hexToUint8Array('000901'); // Declares 2 bytes of data but only provides 1
            expect(() => parseMPI(shortData, 0)).toThrow('Buffer too short to read MPI data.');
        });
    });

    describe('parseVariableLengthField', () => {
        it('should parse a variable length field', () => {
            // Example: OID length 0x08, followed by 8 bytes
            const data = hexToUint8Array('080102030405060708');
            const result = parseVariableLengthField(data, 0);
            expect(result.data).toEqual(hexToUint8Array('0102030405060708'));
            expect(result.bytesRead).toBe(9); // 1 for length, 8 for data
        });
    });

    describe('parseKdfParameters', () => {
        it('should parse KDF parameters', () => {
            // Size 3, Reserved 1, Hash ID 8 (SHA256), Symmetric Algo ID 7 (AES128)
            const data = hexToUint8Array('03010807');
            const result = parseKdfParameters(data, 0);
            expect(result.hashAlgorithmId).toBe(8);
            expect(result.symmetricAlgorithmId).toBe(7);
            expect(result.bytesRead).toBe(4); // 1 for size, 3 for data
        });

         it('should warn for incorrect KDF params size but still parse', () => {
            const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const dataMalformedSize = hexToUint8Array('02010807');

            const resultWithWarn = parseKdfParameters(dataMalformedSize, 0);
            expect(consoleWarnSpy).toHaveBeenCalledWith('parseKdfParameters: Expected KDF parameters size 3, got 2. Parsing will proceed assuming 3.');
            expect(resultWithWarn.hashAlgorithmId).toBe(0x08);
            expect(resultWithWarn.symmetricAlgorithmId).toBe(0x07);
            expect(resultWithWarn.bytesRead).toBe(1 + 2);

            consoleWarnSpy.mockRestore();
        });
    });
});