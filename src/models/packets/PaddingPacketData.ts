
import { Buffer } from 'buffer';
import { IPaddingPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { sliceUint8Array, bufferToHexString } from '../../utils/parserUtils.js';

export class PaddingPacketData extends TBlob implements IPaddingPacketData {
    public paddingContent: Uint8Array;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);
        this.paddingContent = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + dataLength);
    }

    public toJSON() {
        return {
            paddingContent_length: this.paddingContent.length,
            paddingContent_hex_preview: bufferToHexString(this.paddingContent.slice(0, Math.min(32, this.paddingContent.length))) + (this.paddingContent.length > 32 ? "..." : ""),
        };
    }
}
