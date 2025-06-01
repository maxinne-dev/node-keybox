import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PubKeyPacketData } from '../../../models/packets/PubKeyPacketData.js';
import { PublicKeyAlgorithm } from '../../../constants.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';
import { RSAPublicKeyParts } from '../../../models/packets/keyData/RSAPublicKeyParts.js';
import { Ed25519PublicKeyParts } from '../../../models/packets/keyData/Ed25519PublicKeyParts.js';

// Mock the keyData parsers
vi.mock('../../../models/packets/keyData/RSAPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/DSAPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/ElgamalPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/ECDSAPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/EdDSALegacyPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/ECDHPublicKeyParts.js');
vi.mock('../../../models/packets/keyData/X25519PublicKeyParts.js');
vi.mock('../../../models/packets/keyData/X448PublicKeyParts.js');
vi.mock('../../../models/packets/keyData/Ed25519PublicKeyParts.js');
vi.mock('../../../models/packets/keyData/Ed448PublicKeyParts.js');


describe('PubKeyPacketData', () => {
    const keyboxData = new Uint8Array(512); // Dummy buffer
    const testTimestamp = Math.floor(new Date('2023-01-01T00:00:00Z').getTime() / 1000);
    const testTimestampHex = testTimestamp.toString(16).padStart(8, '0');

    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(RSAPublicKeyParts).mockImplementation(() => ({
            totalLength: 258, 
            toJSON: () => ({ type: 'MockedRSAParts' })
        } as any));
        vi.mocked(Ed25519PublicKeyParts).mockImplementation(() => ({
            totalLength: 32, 
            toJSON: () => ({ type: 'MockedEd25519Parts' })
        } as any));
    });

    describe('Version 4 Keys', () => {
        it('should parse a v4 RSA public key packet correctly', () => {
            const rsaAlgoDataHex = 'AA'.repeat(258); 
            const packetDataHex = `04${testTimestampHex}01${rsaAlgoDataHex}`; 
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);

            const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);

            expect(pkData.keyVersion).toBe(4);
            expect(pkData.keyCreationTimestamp).toBe(testTimestamp);
            expect(pkData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.RSA_ENCRYPT_SIGN);
            expect(RSAPublicKeyParts).toHaveBeenCalled();
            expect((pkData.algorithmData as any).toJSON().type).toBe('MockedRSAParts');
        });

        it('should parse a v4 Ed25519 public key packet correctly', () => {
            const ed25519AlgoDataHex = 'BB'.repeat(32);
            const packetDataHex = `04${testTimestampHex}1B${ed25519AlgoDataHex}`; 
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);
            
            const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);

            expect(pkData.keyVersion).toBe(4);
            expect(pkData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.ED25519);
            expect(Ed25519PublicKeyParts).toHaveBeenCalled();
            expect((pkData.algorithmData as any).toJSON().type).toBe('MockedEd25519Parts');
        });
    });

    describe('Version 6 Keys', () => {
        it('should parse a v6 Ed25519 public key packet correctly with material length', () => {
            const ed25519AlgoDataHex = 'CC'.repeat(32);
            const packetDataHex = `06${testTimestampHex}1B00000020${ed25519AlgoDataHex}`;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);

            const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);

            expect(pkData.keyVersion).toBe(6);
            expect(pkData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.ED25519); // Was 32, should be 27 (0x1B)
            expect(Ed25519PublicKeyParts).toHaveBeenCalled();
            expect((pkData.algorithmData as any).toJSON().type).toBe('MockedEd25519Parts');
        });
    });
    
    describe('Version 3 Keys', () => {
        it('should parse a v3 RSA key and skip validity period', () => {
            const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const rsaAlgoDataHex = 'DD'.repeat(258);
            const packetDataHex = `03${testTimestampHex}000001${rsaAlgoDataHex}`;
            const packetDataBytes = hexToUint8Array(packetDataHex);
            keyboxData.set(packetDataBytes, 0);

            const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);

            expect(pkData.keyVersion).toBe(3);
            expect(pkData.publicKeyAlgorithm).toBe(PublicKeyAlgorithm.RSA_ENCRYPT_SIGN);
            expect(RSAPublicKeyParts).toHaveBeenCalled();
            expect(consoleWarnSpy).toHaveBeenCalledWith('PubKeyPacketData: Encountered v3 key with validity period. This field is ignored by this parser.');
            consoleWarnSpy.mockRestore();
        });
    });

    it('should warn for unsupported public key algorithm and store raw data', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const unknownAlgoId = 99;
        const algoDataHex = 'EEFF'.repeat(10);
        const packetDataHex = `04${testTimestampHex}${unknownAlgoId.toString(16).padStart(2, '0')}${algoDataHex}`;
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);

        const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);

        expect(pkData.publicKeyAlgorithm).toBe(unknownAlgoId);
        expect(pkData.algorithmData).toBeInstanceOf(Uint8Array);
        expect(pkData.algorithmData).toEqual(hexToUint8Array(algoDataHex));
        expect(consoleWarnSpy).toHaveBeenCalledWith(`PubKeyPacketData: Unsupported public key algorithm ID: ${unknownAlgoId}. Storing raw algorithm data.`);
        consoleWarnSpy.mockRestore();
    });

    it('should produce correct JSON output', () => {
        const packetDataHex = `04${testTimestampHex}01${'AA'.repeat(258)}`;
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);
        const pkData = new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);
        const json = pkData.toJSON();

        expect(json.keyVersion).toBe(4);
        expect(json.keyCreationDate).toBe(new Date(testTimestamp * 1000).toISOString());
        expect(json.publicKeyAlgorithm).toBe('RSA_ENCRYPT_SIGN');
        expect((json.algorithmData as any).type).toBe('MockedRSAParts');
    });
    
    it('should warn if parsed packet content length does not match declared data length for v4', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        vi.mocked(RSAPublicKeyParts).mockImplementation(() => ({
            totalLength: 200, 
            toJSON: () => ({ type: 'MockedRSAPartsShort' })
        } as any));
        const rsaAlgoDataHex = 'AA'.repeat(258);
        const packetDataHex = `04${testTimestampHex}01${rsaAlgoDataHex}`;
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);

        new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);
        expect(consoleWarnSpy).toHaveBeenCalledWith(`PubKeyPacketData (v3/v4): Parsed packet content length (206) does not match declared data length for packet content (264). There might be extra/unknown data.`);
        consoleWarnSpy.mockRestore();
    });
    
    it('should warn if parsed v6 algorithm data length does not match declared material length', () => {
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        // Mock Ed25519PublicKeyParts to return a totalLength different from what the packet declares
        vi.mocked(Ed25519PublicKeyParts).mockImplementation(() => ({
            totalLength: 30, // Algo parser says it read 30 bytes
            toJSON: () => ({ type: 'MockedEd25519PartsShort' })
        } as any));
        
        const declaredMaterialLength = 32; // The v6 packet declares 32 bytes for the key material
        const ed25519AlgoDataHex = 'CC'.repeat(declaredMaterialLength); // Packet actually contains 32 bytes
        const packetDataHex = `06${testTimestampHex}1B000000${declaredMaterialLength.toString(16).padStart(2,'0')}${ed25519AlgoDataHex}`;
        const packetDataBytes = hexToUint8Array(packetDataHex);
        keyboxData.set(packetDataBytes, 0);

        new PubKeyPacketData(keyboxData, 0, packetDataBytes.length);
        // After parsing, remainingDataLengthForAlgo will be 32 (from the packet).
        // The mocked Ed25519PublicKeyParts constructor will be called with this 32.
        // Its mocked totalLength is 30.
        // So, the warning should compare 30 (parsedAlgoDataLength) with 32 (remainingDataLengthForAlgo).
        expect(consoleWarnSpy).toHaveBeenCalledWith(`PubKeyPacketData (v6): Parsed algorithm data length (30) does not match declared material length (32).`);
        consoleWarnSpy.mockRestore();
    });
});