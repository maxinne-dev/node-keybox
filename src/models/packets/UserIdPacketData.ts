
import { Buffer }from 'buffer';
import { IUserIDPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { bufferToString, sliceUint8Array } from '../../utils/parserUtils.js';

export class UserIdPacketData extends TBlob implements IUserIDPacketData {
    public userId: string;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx); // dataOffsetInKbx is where this packet's specific data begins

        // The entire data section of a User ID packet is the User ID string.
        const userIdBytes = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + dataLength);
        this.userId = bufferToString(userIdBytes, 'utf8');
    }

    public toJSON() {
        return {
            userId: this.userId,
        };
    }
}
