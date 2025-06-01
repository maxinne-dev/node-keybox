
import { Buffer } from 'buffer';
import { 
    ISignaturePacketData, TSignatureAlgorithmData, ISignatureSubpacket,
    IRSASignatureParts, IDSASignatureParts, IEdDSALegacySignatureParts, 
    IEd25519SignatureParts, IEd448SignatureParts
} from '../../types.js';
import { TBlob } from '../TBlob.js';
import { SignatureSubpacket } from './SignatureSubpacket.js';
import { RSASignatureParts } from './signatureData/RSASignatureParts.js';
import { DSASignatureParts } from './signatureData/DSASignatureParts.js';
import { EdDSALegacySignatureParts } from './signatureData/EdDSALegacySignatureParts.js';
import { Ed25519SignatureParts } from './signatureData/Ed25519SignatureParts.js';
import { Ed448SignatureParts } from './signatureData/Ed448SignatureParts.js';
import { readUInt8, readUInt16BE, readUInt32BE, sliceUint8Array, bufferToHexString } from '../../utils/parserUtils.js';
import { PublicKeyAlgorithm, HashAlgorithm as HashAlgorithmEnum, SignatureType as SignatureTypeEnum, V6_SIGNATURE_SALT_SIZES } from '../../constants.js';

export class SignaturePacketData extends TBlob implements ISignaturePacketData {
    public version: number;
    public signatureType: SignatureTypeEnum;
    public publicKeyAlgorithm: PublicKeyAlgorithm;
    public hashAlgorithm: HashAlgorithmEnum;
    
    public hashedSubpacketsCount?: number;
    public hashedSubpackets: SignatureSubpacket[] = [];
    
    public unhashedSubpacketsCount?: number;
    public unhashedSubpackets: SignatureSubpacket[] = [];
    
    public left16BitsSignedHash: Uint8Array;
    
    public creationTimeV3?: number;
    public creationDateV3?: Date;
    public signerKeyIDV3?: Uint8Array;
    
    public saltV6?: Uint8Array;
    
    public signatureAlgorithmData: TSignatureAlgorithmData;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        let currentRelativeOffset = 0;

        this.version = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset));

        if (this.version === 3) {
            const hashedMaterialLength = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset));
            if (hashedMaterialLength !== 5) {
                throw new Error(`SignaturePacketData v3: Expected hashed material length 5, got ${hashedMaterialLength}`);
            }
            this.signatureType = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as SignatureTypeEnum;
            this.creationTimeV3 = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
            this.creationDateV3 = new Date(this.creationTimeV3 * 1000);
            currentRelativeOffset += 4;
            this.signerKeyIDV3 = this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 8);
            currentRelativeOffset += 8;
            this.publicKeyAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as PublicKeyAlgorithm;
            this.hashAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as HashAlgorithmEnum;
            this.left16BitsSignedHash = this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2);
            currentRelativeOffset += 2;
        } else if (this.version === 4 || this.version === 6) {
            this.signatureType = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as SignatureTypeEnum;
            this.publicKeyAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as PublicKeyAlgorithm;
            this.hashAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset)) as HashAlgorithmEnum;

            if (this.version === 4) {
                this.hashedSubpacketsCount = readUInt16BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2));
                currentRelativeOffset += 2;
            } else { // version 6
                this.hashedSubpacketsCount = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
                currentRelativeOffset += 4;
            }
            
            const hashedSubpacketsEnd = currentRelativeOffset + this.hashedSubpacketsCount;
            let currentSubpacketOffset = currentRelativeOffset;
            while (currentSubpacketOffset < hashedSubpacketsEnd) {
                const subpacket = new SignatureSubpacket(this._kbx, this._blobOffset + currentSubpacketOffset, hashedSubpacketsEnd - currentSubpacketOffset);
                this.hashedSubpackets.push(subpacket);
                currentSubpacketOffset += subpacket.totalSubpacketBytes;
            }
            currentRelativeOffset = hashedSubpacketsEnd;

            if (this.version === 4) {
                this.unhashedSubpacketsCount = readUInt16BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2));
                currentRelativeOffset += 2;
            } else { // version 6
                this.unhashedSubpacketsCount = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
                currentRelativeOffset += 4;
            }

            const unhashedSubpacketsEnd = currentRelativeOffset + this.unhashedSubpacketsCount;
            currentSubpacketOffset = currentRelativeOffset;
            while (currentSubpacketOffset < unhashedSubpacketsEnd) {
                 const subpacket = new SignatureSubpacket(this._kbx, this._blobOffset + currentSubpacketOffset, unhashedSubpacketsEnd - currentSubpacketOffset);
                this.unhashedSubpackets.push(subpacket);
                currentSubpacketOffset += subpacket.totalSubpacketBytes;
            }
            currentRelativeOffset = unhashedSubpacketsEnd;

            this.left16BitsSignedHash = this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2);
            currentRelativeOffset += 2;

            if (this.version === 6) {
                const saltSize = readUInt8(this._getRelativeSubarray(currentRelativeOffset, ++currentRelativeOffset));
                const expectedSaltSize = V6_SIGNATURE_SALT_SIZES.get(this.hashAlgorithm);
                if (expectedSaltSize !== undefined && saltSize !== expectedSaltSize) {
                    console.warn(`SignaturePacketData v6: Salt size ${saltSize} for hash algorithm ${HashAlgorithmEnum[this.hashAlgorithm]} (ID ${this.hashAlgorithm}) does not match expected size ${expectedSaltSize}.`);
                } else if (expectedSaltSize === undefined) {
                    console.warn(`SignaturePacketData v6: No expected salt size defined for hash algorithm ${HashAlgorithmEnum[this.hashAlgorithm]} (ID ${this.hashAlgorithm}). Cannot validate salt size ${saltSize}.`);
                }
                this.saltV6 = this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + saltSize);
                currentRelativeOffset += saltSize;
            }
        } else {
            throw new Error(`SignaturePacketData: Unsupported version ${this.version}.`);
        }

        const remainingDataForSigAlgo = dataLength - currentRelativeOffset;
        const sigAlgoDataOffset = this._blobOffset + currentRelativeOffset;

        switch (this.publicKeyAlgorithm) {
            case PublicKeyAlgorithm.RSA_ENCRYPT_SIGN:
            case PublicKeyAlgorithm.RSA_SIGN_ONLY:
                this.signatureAlgorithmData = new RSASignatureParts(this._kbx, sigAlgoDataOffset, remainingDataForSigAlgo);
                break;
            case PublicKeyAlgorithm.DSA_SIGN_ONLY:
            case PublicKeyAlgorithm.ECDSA:
                this.signatureAlgorithmData = new DSASignatureParts(this._kbx, sigAlgoDataOffset, remainingDataForSigAlgo);
                break;
            case PublicKeyAlgorithm.EDDSA_LEGACY:
                this.signatureAlgorithmData = new EdDSALegacySignatureParts(this._kbx, sigAlgoDataOffset, remainingDataForSigAlgo);
                break;
            case PublicKeyAlgorithm.ED25519:
                this.signatureAlgorithmData = new Ed25519SignatureParts(this._kbx, sigAlgoDataOffset, remainingDataForSigAlgo);
                break;
            case PublicKeyAlgorithm.ED448:
                this.signatureAlgorithmData = new Ed448SignatureParts(this._kbx, sigAlgoDataOffset, remainingDataForSigAlgo);
                break;
            default:
                console.warn(`SignaturePacketData: Unsupported public key algorithm ID for signature: ${this.publicKeyAlgorithm}. Storing raw signature data.`);
                this.signatureAlgorithmData = this._getRelativeSubarray(currentRelativeOffset, dataLength);
                break;
        }
        
        if (this.signatureAlgorithmData instanceof Uint8Array) {
            currentRelativeOffset += this.signatureAlgorithmData.length;
        } else {
            currentRelativeOffset += (this.signatureAlgorithmData as any).totalLength;
        }
        
        if (currentRelativeOffset !== dataLength) {
             console.warn(`SignaturePacketData: Parsed packet content length (${currentRelativeOffset}) does not match declared data length for packet content (${dataLength}). Potential extra data or misparsed signature MPIs.`);
        }
    }

    public toJSON() {
        let algoDataJSON;
        if (this.signatureAlgorithmData instanceof Uint8Array) {
            algoDataJSON = `Raw Signature Algo Data (${this.signatureAlgorithmData.length} bytes): ${bufferToHexString(this.signatureAlgorithmData.slice(0,Math.min(16, this.signatureAlgorithmData.length)))}...`;
        } else if (typeof (this.signatureAlgorithmData as any)?.toJSON === 'function') {
            algoDataJSON = (this.signatureAlgorithmData as any).toJSON();
        } else {
            algoDataJSON = this.signatureAlgorithmData;
        }

        const base = {
            version: this.version,
            signatureType: SignatureTypeEnum[this.signatureType] || `Unknown (${this.signatureType})`,
            signatureTypeId: this.signatureType,
            publicKeyAlgorithm: PublicKeyAlgorithm[this.publicKeyAlgorithm] || `Unknown (${this.publicKeyAlgorithm})`,
            publicKeyAlgorithmId: this.publicKeyAlgorithm,
            hashAlgorithm: HashAlgorithmEnum[this.hashAlgorithm] || `Unknown (${this.hashAlgorithm})`,
            hashAlgorithmId: this.hashAlgorithm,
            left16BitsSignedHash_hex: bufferToHexString(this.left16BitsSignedHash),
            signatureAlgorithmData: algoDataJSON,
        };

        if (this.version === 3) {
            return {
                ...base,
                creationTimeV3: this.creationTimeV3,
                creationDateV3: this.creationDateV3?.toISOString(),
                signerKeyIDV3_hex: this.signerKeyIDV3 ? bufferToHexString(this.signerKeyIDV3) : undefined,
            };
        } else { // v4 or v6
            return {
                ...base,
                hashedSubpacketsCount: this.hashedSubpacketsCount,
                hashedSubpackets: this.hashedSubpackets.map(sp => sp.toJSON()),
                unhashedSubpacketsCount: this.unhashedSubpacketsCount,
                unhashedSubpackets: this.unhashedSubpackets.map(sp => sp.toJSON()),
                saltV6_hex: this.saltV6 ? bufferToHexString(this.saltV6) : undefined,
            };
        }
    }
}
