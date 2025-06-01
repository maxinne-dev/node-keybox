
import { Buffer } from 'buffer';
import { IKeyInfo } from '../types.js';
import { TBlob } from './TBlob.js';
import { KEY_INFO_V1_FINGERPRINT_SIZE, KEY_INFO_V2_FINGERPRINT_SIZE, KEY_INFO_V2_KEYGRIP_SIZE } from '../constants.js';
import { readUInt32BE, readUInt16BE, sliceUint8Array } from '../utils/parserUtils.js';

export class KeyInfo extends TBlob implements IKeyInfo {
    public readonly actualSizeInBlob: number;
    private _blobVersion: number; // Version of the parent KeyBlock

    // Parsed fields
    public keyFlagsRaw: Uint8Array;
    public keyFlagsParsed: IKeyInfo['keyFlagsParsed'];

    public fingerprintV1?: Uint8Array;
    public offsetKeyID?: number;

    public fingerprintV2?: Uint8Array;
    public keygrip?: Uint8Array;


    constructor(keyboxData: Uint8Array, blobOffset: number, keyInfoStructSize: number, parentBlobVersion: number) {
        super(keyboxData, blobOffset); // blobOffset is the start of this specific KeyInfo entry
        this.actualSizeInBlob = keyInfoStructSize;
        this._blobVersion = parentBlobVersion;

        if (this._blobVersion === 1) {
            this.fingerprintV1 = this._getRelativeSubarray(0, KEY_INFO_V1_FINGERPRINT_SIZE);
            this.offsetKeyID = readUInt32BE(this._getRelativeSubarray(KEY_INFO_V1_FINGERPRINT_SIZE, KEY_INFO_V1_FINGERPRINT_SIZE + 4));
            this.keyFlagsRaw = this._getRelativeSubarray(KEY_INFO_V1_FINGERPRINT_SIZE + 4, KEY_INFO_V1_FINGERPRINT_SIZE + 4 + 2);
            // RFU is at KEY_INFO_V1_FINGERPRINT_SIZE + 4 + 2, for 2 bytes
        } else if (this._blobVersion === 2) {
            this.fingerprintV2 = this._getRelativeSubarray(0, KEY_INFO_V2_FINGERPRINT_SIZE);
            this.keyFlagsRaw = this._getRelativeSubarray(KEY_INFO_V2_FINGERPRINT_SIZE, KEY_INFO_V2_FINGERPRINT_SIZE + 2);
            // RFU is at KEY_INFO_V2_FINGERPRINT_SIZE + 2, for 2 bytes
            this.keygrip = this._getRelativeSubarray(KEY_INFO_V2_FINGERPRINT_SIZE + 2 + 2, KEY_INFO_V2_FINGERPRINT_SIZE + 2 + 2 + KEY_INFO_V2_KEYGRIP_SIZE);
        } else {
            throw new Error(`KeyInfo: Unsupported parent blob version: ${this._blobVersion}`);
        }
        
        const flags = readUInt16BE(this.keyFlagsRaw);
        this.keyFlagsParsed = {
            qualifiedSignature: (flags & 0x0001) !== 0,
        };
        if (this._blobVersion === 2) {
            this.keyFlagsParsed.is32ByteFingerprintInUse = (flags & 0x0080) !== 0; // Bit 7
        }
    }
    
    public toJSON() {
        const common = {
            actualSizeInBlob: this.actualSizeInBlob,
            keyFlagsRaw: Buffer.from(this.keyFlagsRaw).toString('hex'),
            keyFlagsParsed: this.keyFlagsParsed,
        };
        if (this._blobVersion === 1) {
            return {
                ...common,
                blobVersion: 1 as const,
                fingerprintV1: this.fingerprintV1 ? Buffer.from(this.fingerprintV1).toString('hex') : undefined,
                offsetKeyID: this.offsetKeyID,
            };
        } else {
            return {
                ...common,
                blobVersion: 2 as const,
                fingerprintV2: this.fingerprintV2 ? Buffer.from(this.fingerprintV2).toString('hex') : undefined,
                keygrip: this.keygrip ? Buffer.from(this.keygrip).toString('hex') : undefined,
            };
        }
    }
}
