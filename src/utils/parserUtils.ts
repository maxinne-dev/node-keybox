import { Buffer } from 'buffer'; // Ensure buffer is available, especially in browser environments if not polyfilled

export function readUInt8(buffer: Uint8Array, offset: number = 0): number {
    return Buffer.from(buffer).readUInt8(offset);
}

export function readUInt16BE(buffer: Uint8Array, offset: number = 0): number {
    return Buffer.from(buffer).readUInt16BE(offset);
}

export function readUInt16LE(buffer: Uint8Array, offset: number = 0): number {
    return Buffer.from(buffer).readUInt16LE(offset);
}

export function readUInt32BE(buffer: Uint8Array, offset: number = 0): number {
    return Buffer.from(buffer).readUInt32BE(offset);
}

export function bufferToString(buffer: Uint8Array, encoding: BufferEncoding = 'utf8'): string {
    return Buffer.from(buffer).toString(encoding);
}

export function sliceUint8Array(source: Uint8Array, start: number, end: number): Uint8Array {
    // Uint8Array.prototype.slice creates a copy, which is good.
    return source.slice(start, end);
}

/**
 * Parses a Multiprecision Integer (MPI) from a buffer at a given offset.
 * An MPI consists of a 2-octet length (in bits), followed by the integer bytes.
 * @param fullBuffer The buffer containing the MPI.
 * @param absoluteOffset The absolute offset in fullBuffer where the MPI's 2-byte length field begins.
 * @returns An object containing the full MPI (including length prefix), its bitLength,
 *          total bytesRead for this MPI, and the raw value bytes of the MPI.
 * @throws Error if buffer is too short to read MPI length or data.
 */
export function parseMPI(
    fullBuffer: Uint8Array,
    absoluteOffset: number
): { mpi: Uint8Array; bitLength: number; bytesRead: number; mpiValueBytes: Uint8Array } {
    if (absoluteOffset + 2 > fullBuffer.length) {
        throw new Error('parseMPI: Buffer too short to read MPI bit length.');
    }
    const bitLength = readUInt16BE(fullBuffer, absoluteOffset);
    const byteLength = Math.ceil(bitLength / 8);
    const totalBytesForMPI = 2 + byteLength;

    console.debug(`parseMPI: rawData=${Buffer.from(fullBuffer.slice(absoluteOffset, absoluteOffset + 10)).toString('hex')}, bitLength=${bitLength}, byteLength=${byteLength}`);
    console.debug(`parseMPI: bitLength=${bitLength}, byteLength=${byteLength}, totalBytesForMPI=${totalBytesForMPI}`);

    if (absoluteOffset + totalBytesForMPI > fullBuffer.length) {
        throw new Error(`parseMPI: Buffer too short to read MPI data. Need ${totalBytesForMPI}, have ${fullBuffer.length - absoluteOffset}.`);
    }

    const mpiValueBytes = sliceUint8Array(fullBuffer, absoluteOffset + 2, absoluteOffset + 2 + byteLength);
    const mpi = sliceUint8Array(fullBuffer, absoluteOffset, absoluteOffset + totalBytesForMPI);

    return {
        mpi,
        bitLength,
        bytesRead: totalBytesForMPI,
        mpiValueBytes,
    };
}

/**
 * Parses a variable-length field, typically an OID for EC keys.
 * Format: 1-octet length, followed by data of that length.
 * @param fullBuffer The buffer containing the data.
 * @param absoluteOffset The absolute offset in fullBuffer where the 1-byte length field begins.
 * @returns An object containing the data and total bytes read.
 * @throws Error if buffer is too short.
 */
export function parseVariableLengthField(
    fullBuffer: Uint8Array,
    absoluteOffset: number
): { data: Uint8Array; bytesRead: number } {
    if (absoluteOffset + 1 > fullBuffer.length) {
        throw new Error('parseVariableLengthField: Buffer too short to read length octet.');
    }
    const length = readUInt8(fullBuffer, absoluteOffset);
    const totalBytesRead = 1 + length;

    if (absoluteOffset + totalBytesRead > fullBuffer.length) {
        throw new Error('parseVariableLengthField: Buffer too short to read data.');
    }

    const data = sliceUint8Array(fullBuffer, absoluteOffset + 1, absoluteOffset + totalBytesRead);
    return { data, bytesRead: totalBytesRead };
}

/**
 * Parses KDF parameters for ECDH public keys from a buffer at a given offset.
 * Format: 1-octet size of (reserved_octet + hash_id_octet + sym_algo_id_octet),
 *         1-octet reserved (value 1),
 *         1-octet hash function ID,
 *         1-octet symmetric algorithm ID.
 * @param fullBuffer The buffer containing the KDF parameters.
 * @param absoluteOffset The absolute offset in fullBuffer where the KDF parameters structure begins.
 * @returns An object containing the hashId, symmetricAlgorithmId, and total bytesRead.
 * @throws Error if buffer is too short or KDF structure is malformed.
 */
export function parseKdfParameters(
    fullBuffer: Uint8Array,
    absoluteOffset: number
): { hashAlgorithmId: number; symmetricAlgorithmId: number; bytesRead: number } {
    // Minimum length: 1 (size) + 1 (reserved) + 1 (hashId) + 1 (symAlgoId) = 4
    if (absoluteOffset + 1 > fullBuffer.length) {
         throw new Error('parseKdfParameters: Buffer too short to read KDF parameters size octet.');
    }
    const kdfParamsSize = readUInt8(fullBuffer, absoluteOffset); // Size of the 3 following fields
    
    if (kdfParamsSize !== 3) { // As per RFC 9580 section 5.5.5.6 for ECDH
        console.warn(`parseKdfParameters: Expected KDF parameters size 3, got ${kdfParamsSize}. Parsing will proceed assuming 3.`);
        // Strict parsing would throw here. For robustness, we can try to proceed if overall data length allows.
    }

    const totalBytesReadForKdfStruct = 1 + kdfParamsSize; // 1 for size octet + kdfParamsSize for its content

    if (absoluteOffset + totalBytesReadForKdfStruct > fullBuffer.length) {
        throw new Error('parseKdfParameters: Buffer too short for KDF parameters content.');
    }
    
    // const reservedOctet = readUInt8(fullBuffer, absoluteOffset + 1); // Should be 1
    // if (reservedOctet !== 1) {
    //     console.warn(`parseKdfParameters: KDF reserved octet is ${reservedOctet}, expected 1.`);
    // }
    
    const hashAlgorithmId = readUInt8(fullBuffer, absoluteOffset + 1 + 1); // 1 for size, 1 for reserved
    const symmetricAlgorithmId = readUInt8(fullBuffer, absoluteOffset + 1 + 1 + 1); // 1 for size, 1 for reserved, 1 for hashId

    return {
        hashAlgorithmId,
        symmetricAlgorithmId,
        bytesRead: totalBytesReadForKdfStruct,
    };
}