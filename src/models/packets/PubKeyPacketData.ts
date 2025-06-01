
import { Buffer } from 'buffer';
import { IPublicKeyPacketData, TPublicKeyAlgorithmData, IRSAPublicKeyParts, IDSAPublicKeyParts, IElgamalPublicKeyParts, IECDSAPublicKeyParts, IEdDSALegacyPublicKeyParts, IECDHPublicKeyParts, IX25519PublicKeyParts, IX448PublicKeyParts, IEd25519PublicKeyParts, IEd448PublicKeyParts } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { PublicKeyAlgorithm } from '../../constants.js';
import { RSAPublicKeyParts } from './keyData/RSAPublicKeyParts.js';
import { DSAPublicKeyParts } from './keyData/DSAPublicKeyParts.js';
import { ElgamalPublicKeyParts } from './keyData/ElgamalPublicKeyParts.js';
import { ECDSAPublicKeyParts } from './keyData/ECDSAPublicKeyParts.js';
import { EdDSALegacyPublicKeyParts } from './keyData/EdDSALegacyPublicKeyParts.js';
import { ECDHPublicKeyParts } from './keyData/ECDHPublicKeyParts.js';
import { X25519PublicKeyParts } from './keyData/X25519PublicKeyParts.js';
import { X448PublicKeyParts } from './keyData/X448PublicKeyParts.js';
import { Ed25519PublicKeyParts } from './keyData/Ed25519PublicKeyParts.js';
import { Ed448PublicKeyParts } from './keyData/Ed448PublicKeyParts.js';
import { readUInt8, readUInt32BE, sliceUint8Array } from '../../utils/parserUtils.js';

export class PubKeyPacketData extends TBlob implements IPublicKeyPacketData {
    public keyVersion: number;
    public keyCreationTimestamp: number;
    public keyCreationDate: Date;
    public publicKeyAlgorithm: PublicKeyAlgorithm;
    public algorithmData: TPublicKeyAlgorithmData;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx); // dataOffsetInKbx is where this packet's specific data begins

        let currentRelativeOffset = 0;

        this.keyVersion = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
        currentRelativeOffset += 1;

        if (this.keyVersion !== 4 && this.keyVersion !== 3 && this.keyVersion !== 5 && this.keyVersion !== 6) { 
            // Keybox spec mainly refers to v4 keys. GnuPG might produce other versions.
            // RFC 9580 introduces v6 keys.
            console.warn(`PubKeyPacketData: Parsing PublicKey Packet version ${this.keyVersion}. Support might be limited for non-v4/v6.`);
        }
        
        this.keyCreationTimestamp = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
        currentRelativeOffset += 4;
        this.keyCreationDate = new Date(this.keyCreationTimestamp * 1000);

        // For v3 keys, there's a 2-octet "days valid" field here. This parser assumes v4+.
        if (this.keyVersion === 3) {
            // daysValid = readUInt16BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 2));
            currentRelativeOffset += 2; 
            console.warn(`PubKeyPacketData: Encountered v3 key with validity period. This field is ignored by this parser.`);
        }
        
        // For v6 keys, there is a 4-octet scalar octet count for the public key material.
        let publicKeyMaterialLength = dataLength - currentRelativeOffset -1; // Default for v4 (algo byte + rest)
        if (this.keyVersion === 6) {
            const materialCount = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
            currentRelativeOffset += 4;
            publicKeyMaterialLength = materialCount; 
            // The -1 for algo byte will be applied after reading the algo byte
        }


        this.publicKeyAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1)) as PublicKeyAlgorithm;
        currentRelativeOffset += 1;
        
        // Adjust remainingDataLength based on key version specifics
        const algorithmSpecificDataOffset = this._blobOffset + currentRelativeOffset;
        let remainingDataLengthForAlgo = dataLength - currentRelativeOffset;
        if (this.keyVersion === 6) {
            remainingDataLengthForAlgo = publicKeyMaterialLength; // Use the explicit count for v6
        }


        switch (this.publicKeyAlgorithm) {
            case PublicKeyAlgorithm.RSA_ENCRYPT_SIGN:
            case PublicKeyAlgorithm.RSA_ENCRYPT_ONLY:
            case PublicKeyAlgorithm.RSA_SIGN_ONLY:
                this.algorithmData = new RSAPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IRSAPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.DSA_SIGN_ONLY:
                this.algorithmData = new DSAPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IDSAPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.ELGAMAL_ENCRYPT_ONLY:
                this.algorithmData = new ElgamalPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IElgamalPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.ECDSA:
                this.algorithmData = new ECDSAPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IECDSAPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.EDDSA_LEGACY: // EdDSALegacy
                this.algorithmData = new EdDSALegacyPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IEdDSALegacyPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.ECDH:
                this.algorithmData = new ECDHPublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IECDHPublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.X25519:
                this.algorithmData = new X25519PublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IX25519PublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.X448:
                this.algorithmData = new X448PublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IX448PublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.ED25519:
                this.algorithmData = new Ed25519PublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IEd25519PublicKeyParts).totalLength;
                break;
            case PublicKeyAlgorithm.ED448:
                this.algorithmData = new Ed448PublicKeyParts(this._kbx, algorithmSpecificDataOffset, remainingDataLengthForAlgo);
                currentRelativeOffset += (this.algorithmData as IEd448PublicKeyParts).totalLength;
                break;
            default:
                console.warn(`PubKeyPacketData: Unsupported public key algorithm ID: ${this.publicKeyAlgorithm}. Storing raw algorithm data.`);
                this.algorithmData = this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + remainingDataLengthForAlgo);
                currentRelativeOffset += remainingDataLengthForAlgo;
                break;
        }

        if (currentRelativeOffset !== dataLength) {
            // For v6, dataLength is the length of the whole PubKeyPacketData content.
            // currentRelativeOffset is offset within that.
            // The check should be if the read algo data length + initial fields equals dataLength (for v4/v3)
            // or if read algo data length matches publicKeyMaterialLength (for v6)
            if (this.keyVersion === 6) {
                if ((this.algorithmData as any).totalLength !== remainingDataLengthForAlgo) {
                     console.warn(`PubKeyPacketData (v6): Parsed algorithm data length (${(this.algorithmData as any).totalLength}) does not match declared material length (${remainingDataLengthForAlgo}).`);
                }
            } else { // v3/v4
                 if (currentRelativeOffset !== dataLength) {
                    console.warn(`PubKeyPacketData (v3/v4): Parsed packet content length (${currentRelativeOffset}) does not match declared data length for packet content (${dataLength}). There might be extra/unknown data.`);
                }
            }
        }
    }

    public toJSON() {
        let algoDataJSON;
        if (this.algorithmData instanceof Uint8Array) {
            algoDataJSON = `Raw Algorithm Data (${this.algorithmData.length} bytes): ${Buffer.from(this.algorithmData.slice(0,Math.min(16,this.algorithmData.length))).toString('hex')}...`;
        } else if (typeof (this.algorithmData as any)?.toJSON === 'function') {
            algoDataJSON = (this.algorithmData as any).toJSON();
        } else {
            algoDataJSON = this.algorithmData;
        }

        return {
            keyVersion: this.keyVersion,
            keyCreationTimestamp: this.keyCreationTimestamp,
            keyCreationDate: this.keyCreationDate.toISOString(),
            publicKeyAlgorithm: PublicKeyAlgorithm[this.publicKeyAlgorithm] || `Unknown (${this.publicKeyAlgorithm})`,
            publicKeyAlgorithmId: this.publicKeyAlgorithm,
            algorithmData: algoDataJSON,
        };
    }
}