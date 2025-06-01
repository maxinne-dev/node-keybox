
import { Buffer } from 'buffer';
import { ITrustPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { sliceUint8Array } from '../../utils/parserUtils.js';

export class TrustPacketData extends TBlob implements ITrustPacketData {
    public trustData: Uint8Array;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx); // dataOffsetInKbx is where this packet's specific data begins

        // The entire data section of a Trust packet is the trust data.
        this.trustData = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + dataLength);
    }

    public toJSON() {
        return {
            trustData_hex: Buffer.from(this.trustData).toString('hex'),
            trustData_length: this.trustData.length,
        };
    }
}
