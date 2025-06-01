
import { Buffer } from 'buffer';
import { ISEIPDData, ISEIPDDataV1, ISEIPDDataV2 } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { SEIPD_VERSION_1, SEIPD_VERSION_2, AEAD_AUTH_TAG_LENGTH, SymmetricKeyAlgorithm as SKAlgorithmEnum, AEADAlgorithm as AEADAlgorithmEnum } from '../../constants.js';
import { readUInt8, sliceUint8Array } from '../../utils/parserUtils.js';

export class SEIPDData extends TBlob implements ISEIPDData {
    public version: number;
    public data: ISEIPDDataV1 | ISEIPDDataV2;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength < 1) {
            throw new Error("SEIPDData: Data length too short for version.");
        }

        this.version = readUInt8(this._getRelativeSubarray(0, 1));
        let currentRelativeOffset = 1;

        if (this.version === SEIPD_VERSION_1) {
            if (currentRelativeOffset > dataLength) {
                 throw new Error("SEIPDData v1: Data length too short.");
            }
            this.data = {
                encryptedDataAndMDC: sliceUint8Array(this._kbx, this._blobOffset + currentRelativeOffset, this._blobOffset + dataLength),
            };
        } else if (this.version === SEIPD_VERSION_2) {
            // Expected: cipherAlgo(1) + aeadAlgo(1) + chunkSizeOctet(1) + salt(32) + finalAuthTag(AEAD_AUTH_TAG_LENGTH)
            const minV2DataSize = 1 + 1 + 1 + 32 + AEAD_AUTH_TAG_LENGTH;
            if (dataLength < currentRelativeOffset + minV2DataSize -1) { // -1 because currentRelativeOffset is already 1
                throw new Error(`SEIPDData v2: Data portion length ${dataLength - currentRelativeOffset} too short for minimal fields and tag (needs at least ${minV2DataSize}).`);
            }

            const cipherAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1)) as SKAlgorithmEnum;
            currentRelativeOffset += 1;

            const aeadAlgorithm = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1)) as AEADAlgorithmEnum;
            currentRelativeOffset += 1;

            const chunkSizeOctet = readUInt8(this._getRelativeSubarray(currentRelativeOffset, currentRelativeOffset + 1));
            currentRelativeOffset += 1;

            const salt = sliceUint8Array(this._kbx, this._blobOffset + currentRelativeOffset, this._blobOffset + currentRelativeOffset + 32);
            currentRelativeOffset += 32;
            
            const encryptedDataEndOffsetInData = dataLength - AEAD_AUTH_TAG_LENGTH; // end relative to start of packet data
            if (currentRelativeOffset > encryptedDataEndOffsetInData) {
                 throw new Error(`SEIPDData v2: Offset for encrypted data start (${currentRelativeOffset}) exceeds end of encrypted data section (${encryptedDataEndOffsetInData}). dataLength: ${dataLength}`);
            }

            const encryptedDataWithChunkTags = sliceUint8Array(this._kbx, this._blobOffset + currentRelativeOffset, this._blobOffset + encryptedDataEndOffsetInData);
            
            const finalAuthenticationTag = sliceUint8Array(this._kbx, this._blobOffset + encryptedDataEndOffsetInData, this._blobOffset + dataLength);

            this.data = {
                cipherAlgorithm,
                aeadAlgorithm,
                chunkSizeOctet,
                salt,
                encryptedDataWithChunkTags,
                finalAuthenticationTag,
            };
        } else {
            throw new Error(`SEIPDData: Unsupported version ${this.version}.`);
        }
    }

    public toJSON() {
        if (this.version === SEIPD_VERSION_1) {
            const v1Data = this.data as ISEIPDDataV1;
            return {
                version: this.version,
                data: {
                    encryptedDataAndMDC_length: v1Data.encryptedDataAndMDC.length,
                    encryptedDataAndMDC_hex_preview: Buffer.from(v1Data.encryptedDataAndMDC.slice(0, Math.min(32, v1Data.encryptedDataAndMDC.length))).toString('hex') + (v1Data.encryptedDataAndMDC.length > 32 ? "..." : ""),
                }
            };
        } else if (this.version === SEIPD_VERSION_2) {
            const v2Data = this.data as ISEIPDDataV2;
            return {
                version: this.version,
                data: {
                    cipherAlgorithm: SKAlgorithmEnum[v2Data.cipherAlgorithm] || `Unknown (${v2Data.cipherAlgorithm})`,
                    cipherAlgorithmId: v2Data.cipherAlgorithm,
                    aeadAlgorithm: AEADAlgorithmEnum[v2Data.aeadAlgorithm] || `Unknown (${v2Data.aeadAlgorithm})`,
                    aeadAlgorithmId: v2Data.aeadAlgorithm,
                    chunkSizeOctet: v2Data.chunkSizeOctet,
                    chunkSizeActual: (1 << (v2Data.chunkSizeOctet + 6)),
                    salt_hex: Buffer.from(v2Data.salt).toString('hex'),
                    encryptedDataWithChunkTags_length: v2Data.encryptedDataWithChunkTags.length,
                    finalAuthenticationTag_hex: Buffer.from(v2Data.finalAuthenticationTag).toString('hex'),
                }
            };
        }
        return { version: this.version, data: "Unknown version data" };
    }
}
