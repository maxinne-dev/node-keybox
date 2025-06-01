
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
import { readUInt8, readUInt32BE, sliceUint8Array, bufferToHexString } from '../../utils/parserUtils.js';

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
            console.warn(`PubKeyPacketData: Parsing PublicKey Packet version ${this.keyVersion}. Support might be limited for non-v4/v6.`);
        }
        
        this.keyCreationTimestamp = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
        currentRelativeOffset += 4;
        this.keyCreationDate = new Date(this.keyCreationTimestamp * 1000);

        if (this.keyVersion === 3) {
            currentRelativeOffset += 2; 
            console.warn(`PubKeyPacketData: Encountered v3 key with validity period. This field is ignored by this parser.`);
        }
        
        this.publicKeyAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1)) as PublicKeyAlgorithm;
        currentRelativeOffset += 1;

        let publicKeyMaterialLength: number;
        if (this.keyVersion === 6) {
            const materialCount = readUInt32BE(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 4));
            currentRelativeOffset += 4;
            publicKeyMaterialLength = materialCount; 
        } else {
            // For v3/v4, the remaining data length is for the algorithm-specific parts
            publicKeyMaterialLength = dataLength - currentRelativeOffset;
        }
        
        const algorithmSpecificDataOffset = this._blobOffset + currentRelativeOffset;
        const remainingDataLengthForAlgo = publicKeyMaterialLength;


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
                this.algorithmData = sliceUint8Array(this._kbx, algorithmSpecificDataOffset, algorithmSpecificDataOffset + remainingDataLengthForAlgo);
                currentRelativeOffset += remainingDataLengthForAlgo;
                break;
        }
        
        // For v6, the algorithm data length should match the declared material length.
        // For v3/v4, the total currentRelativeOffset should match dataLength.
        if (this.keyVersion === 6) {
            // The `currentRelativeOffset` here is the offset *after* parsing algorithm data.
            // The length of the algorithm data itself is `(this.algorithmData as any).totalLength` or `remainingDataLengthForAlgo` if it's raw.
            let parsedAlgoDataLength = 0;
            if (this.algorithmData instanceof Uint8Array) {
                parsedAlgoDataLength = this.algorithmData.length;
            } else if ((this.algorithmData as any).totalLength !== undefined) {
                parsedAlgoDataLength = (this.algorithmData as any).totalLength;
            }

            if (parsedAlgoDataLength !== remainingDataLengthForAlgo) { // remainingDataLengthForAlgo is publicKeyMaterialLength for v6
                 console.warn(`PubKeyPacketData (v6): Parsed algorithm data length (${parsedAlgoDataLength}) does not match declared material length (${remainingDataLengthForAlgo}).`);
            }
        } else { // v3/v4
             if (currentRelativeOffset !== dataLength) {
                console.warn(`PubKeyPacketData (v3/v4): Parsed packet content length (${currentRelativeOffset}) does not match declared data length for packet content (${dataLength}). There might be extra/unknown data.`);
            }
        }
    }

    public toJSON() {
        let algoDataJSON;
        if (this.algorithmData instanceof Uint8Array) {
            algoDataJSON = `Raw Algorithm Data (${this.algorithmData.length} bytes): ${bufferToHexString(this.algorithmData.slice(0,Math.min(16,this.algorithmData.length)))}...`;
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
