
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SignaturePacketData } from '../../../models/packets/SignaturePacketData.js';
import { PublicKeyAlgorithm, HashAlgorithm, SignatureType, SignatureSubpacketType } from '../../../constants.js';
import { hexToUint8Array, u8 } from '../../test-utils.js';
import { Buffer } from 'buffer';
import { RSASignatureParts } from '../../../models/packets/signatureData/RSASignatureParts.js';
import { Ed25519SignatureParts } from '../../../models/packets/signatureData/Ed25519SignatureParts.js';
import { SignatureSubpacket } from '../../../models/packets/SignatureSubpacket.js';

// Define expected JSON shapes for clarity in tests
// Base properties common to all JSON outputs from SignaturePacketData's toJSON
type SignaturePacketJSONBase = {
    version: number;
    signatureType: string;
    signatureTypeId: SignatureType;
    publicKeyAlgorithm: string;
    publicKeyAlgorithmId: PublicKeyAlgorithm;
    hashAlgorithm: string;
    hashAlgorithmId: HashAlgorithm;
    left16BitsSignedHash_hex: string;
    signatureAlgorithmData: any; // Can be more specific if needed
};

// V3 specific properties
type SignaturePacketV3JSON = SignaturePacketJSONBase & {
    creationTimeV3?: number;
    creationDateV3?: string;
    signerKeyIDV3_hex?: string;
};

// V4/V6 specific properties
type SignaturePacketV4V6JSON = SignaturePacketJSONBase & {
    hashedSubpacketsCount?: number;
    hashedSubpackets: any[]; // Array of subpacket JSONs
    unhashedSubpacketsCount?: number;
    unhashedSubpackets: any[]; // Array of subpacket JSONs
    saltV6_hex?: string;
};


// Mock dependencies
vi.mock('../../../models/packets/SignatureSubpacket.js');
vi.mock('../../../models/packets/signatureData/RSASignatureParts.js');
vi.mock('../../../models/packets/signatureData/DSASignatureParts.js');
vi.mock('../../../models/packets/signatureData/EdDSALegacySignatureParts.js');
vi.mock('../../../models/packets/signatureData/Ed25519SignatureParts.js');
vi.mock('../../../models/packets/signatureData/Ed448SignatureParts.js');

describe('SignaturePacketData', () => {
    const keyboxData = new Uint8Array(1024); // Dummy buffer
    const testCreationTime = Math.floor(new Date('2023-03-01T12:00:00Z').getTime() / 1000);
    const testCreationTimeHex = testCreationTime.toString(16).padStart(8, '0');
    const left16BitsHashHex = "1234";

    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(RSASignatureParts).mockImplementation(() => ({
            totalLength: 256, // Mocked length e.g. 2048-bit RSA sig
            toJSON: () => ({ type: 'MockedRSASigParts' })
        } as any));
        vi.mocked(Ed25519SignatureParts).mockImplementation(() => ({
            totalLength: 64,
            toJSON: () => ({ type: 'MockedEd25519SigParts' })
        } as any));
        vi.mocked(SignatureSubpacket).mockImplementation((_kbx, _offset, _maxLen) => {
            // A simple mock: assume it consumes a fixed amount for testing offsets
            // For a real test, we'd need more complex subpacket data.
            // Let's say each mocked subpacket is 3 bytes total (1 len, 1 type, 1 data)
            return {
                totalSubpacketBytes: 3, 
                type: SignatureSubpacketType.SIGNATURE_CREATION_TIME, // Arbitrary
                toJSON: () => ({ type: 'MockedSubpacket', length: 3 })
            } as any;
        });
    });

    describe('Version 3 Signatures', () => {
        it('should parse a v3 RSA signature correctly', () => {
            const signerKeyIDHex = "AABBCCDDEEFF0011";
            const rsaSigDataHex = "00".repeat(256); // Mock
            
            // v3, hashed_len(5), sigType(0x00), creationTime, signerKeyID, pkAlgo(RSA), hashAlgo(SHA256), left16bits, sigMPI
            const packetDataHex = 
                "03" + "05" + "00" + testCreationTimeHex + signerKeyIDHex + 
                PublicKeyAlgorithm.RSA_ENCRYPT_SIGN.toString(16).padStart(2, '0') + 
                HashAlgorithm.SHA256.toString(16).padStart(2, '0') + 
                left16BitsHashHex + 
                rsaSigDataHex;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);
            
            vi.mocked(RSASignatureParts).mockImplementation(() => ({ totalLength: 256, toJSON: () => ({}) } as any));

            const sigData = new SignaturePacketData(keyboxData, 0, packetDataBytes.length);

            expect(sigData.version).toBe(3);
            expect(sigData.signatureType).toBe(SignatureType.BINARY_DOCUMENT);
            expect(sigData.creationTimeV3).toBe(testCreationTime);
            expect(sigData.signerKeyIDV3).toEqual(hexToUint8Array(signerKeyIDHex));
            expect(sigData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.RSA_ENCRYPT_SIGN);
            expect(sigData.hashAlgorithm).toBe(HashAlgorithm.SHA256);
            expect(sigData.left16BitsSignedHash).toEqual(hexToUint8Array(left16BitsHashHex));
            expect(RSASignatureParts).toHaveBeenCalled();
        });
    });

    describe('Version 4 Signatures', () => {
        it('should parse a v4 Ed25519 signature with subpackets', () => {
            const hashedSubpacketsCount = 3; // 1 mocked subpacket
            const unhashedSubpacketsCount = 0; 
            const ed25519SigHex = "00".repeat(64);

            // v4, sigType(0x01), pkAlgo(Ed25519), hashAlgo(SHA512), 
            // hashed_count(2B), [hashed_subpacket_data], 
            // unhashed_count(2B), [unhashed_subpacket_data], 
            // left16bits, ed25519_sig
            const packetDataHex = 
                "04" + "01" + 
                PublicKeyAlgorithm.ED25519.toString(16).padStart(2, '0') + 
                HashAlgorithm.SHA512.toString(16).padStart(2, '0') +
                hashedSubpacketsCount.toString(16).padStart(4, '0') + /* hashed_subpacket_data (mocked as 3 bytes) */ "00".repeat(3) +
                unhashedSubpacketsCount.toString(16).padStart(4, '0') + /* no unhashed */
                left16BitsHashHex + 
                ed25519SigHex;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);
            
            vi.mocked(Ed25519SignatureParts).mockImplementation(() => ({ totalLength: 64, toJSON: () => ({}) } as any));

            const sigData = new SignaturePacketData(keyboxData, 0, packetDataBytes.length);

            expect(sigData.version).toBe(4);
            expect(sigData.signatureType).toBe(SignatureType.CANONICAL_TEXT_DOCUMENT);
            expect(sigData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.ED25519);
            expect(sigData.hashAlgorithm).toBe(HashAlgorithm.SHA512);
            expect(sigData.hashedSubpackets.length).toBe(1); // Mock consumes 3 bytes
            expect(sigData.unhashedSubpackets.length).toBe(0);
            expect(SignatureSubpacket).toHaveBeenCalledTimes(1); // Once for hashed
            expect(Ed25519SignatureParts).toHaveBeenCalled();
        });
    });
    
    describe('Version 6 Signatures', () => {
        it('should parse a v6 Ed25519 signature with salt and subpackets', () => {
            const hashedSubpacketsCount = 6; // 2 mocked subpackets
            const unhashedSubpacketsCount = 3; // 1 mocked subpacket
            const saltHex = "112233445566778899AABBCCDDEEFF00"; // 16-byte salt for SHA256
            const ed25519SigHex = "00".repeat(64);

            // v6, sigType, pkAlgo(Ed25519), hashAlgo(SHA256 for this salt len)
            // hashed_count(4B), [hashed_sp_data], unhashed_count(4B), [unhashed_sp_data]
            // left16bits, salt_size(1B), salt, ed25519_sig
            const packetDataHex = 
                "06" + "10" + // SigType GENERIC_CERTIFICATION
                PublicKeyAlgorithm.ED25519.toString(16).padStart(2, '0') + 
                HashAlgorithm.SHA256.toString(16).padStart(2, '0') + // SHA256 expects 16-byte salt
                hashedSubpacketsCount.toString(16).padStart(8, '0') + "00".repeat(6) + // 2 mocked subpackets
                unhashedSubpacketsCount.toString(16).padStart(8, '0') + "00".repeat(3) + // 1 mocked subpacket
                left16BitsHashHex +
                "10" + saltHex + // Salt size 16 (0x10)
                ed25519SigHex;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);

            vi.mocked(Ed25519SignatureParts).mockImplementation(() => ({ totalLength: 64, toJSON: () => ({}) }as any));

            const sigData = new SignaturePacketData(keyboxData, 0, packetDataBytes.length);
            
            expect(sigData.version).toBe(6);
            expect(sigData.saltV6).toEqual(hexToUint8Array(saltHex));
            expect(sigData.hashedSubpackets.length).toBe(2);
            expect(sigData.unhashedSubpackets.length).toBe(1);
            expect(SignatureSubpacket).toHaveBeenCalledTimes(3);
            expect(Ed25519SignatureParts).toHaveBeenCalled();
        });
    });

    it('should throw for unsupported signature version', () => {
        const packetDataBytes = hexToUint8Array("05" + "00".repeat(10)); // Version 5
        keyboxData.set(packetDataBytes, 0);
        expect(() => new SignaturePacketData(keyboxData, 0, packetDataBytes.length))
            .toThrow('SignaturePacketData: Unsupported version 5.');
    });

    it('should handle unknown public key algorithm for signature data', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const unknownPkAlgo = PublicKeyAlgorithm.ELGAMAL_ENCRYPT_ONLY; // Not typically for signing
        const sigAlgoDataHex = "00".repeat(10);
        const packetDataHex = 
            "04" + "00" + 
            unknownPkAlgo.toString(16).padStart(2, '0') + 
            HashAlgorithm.SHA256.toString(16).padStart(2, '0') +
            "0000" + "0000" + // No subpackets
            left16BitsHashHex + 
            sigAlgoDataHex;
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);

        const sigData = new SignaturePacketData(keyboxData, 0, packetDataBytes.length);
        
        expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining(`Unsupported public key algorithm ID for signature: ${unknownPkAlgo}`));
        expect(sigData.signatureAlgorithmData).toBeInstanceOf(Uint8Array);
        expect(sigData.signatureAlgorithmData).toEqual(hexToUint8Array(sigAlgoDataHex));
        consoleWarnSpy.mockRestore();
    });

    it('should produce correct JSON output for v4', () => {
        const packetDataHex = 
            "0401" + PublicKeyAlgorithm.ED25519.toString(16).padStart(2,'0') + HashAlgorithm.SHA512.toString(16).padStart(2,'0') +
            "0003" + "DDEEFF" + // Hashed subpacket (mocked 3 bytes)
            "0000" + // No unhashed
            left16BitsHashHex + "00".repeat(64); // Ed25519 sig
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        const sigData = new SignaturePacketData(keyboxData, 0, packetDataBytes.length);
        const json = sigData.toJSON();

        expect(json.version).toBe(4);
        expect(json.signatureType).toBe('CANONICAL_TEXT_DOCUMENT');
        if (json.version === 4 || json.version === 6) {
            // Explicitly cast to the V4V6 JSON type to access hashedSubpackets
            const v4v6Json = json as SignaturePacketV4V6JSON;
            expect(v4v6Json.hashedSubpackets.length).toBe(1);
        } else {
            expect.fail("JSON version mismatch");
        }
        expect((json.signatureAlgorithmData as any).type).toBe('MockedEd25519SigParts');
    });
});
