
import { Buffer } from 'buffer';
import { IMarkerPacketData } from '../../types.js';
import { TBlob } from '../TBlob.js';
import { MARKER_PACKET_CONTENT } from '../../constants.js';
import { bufferToString, sliceUint8Array } from '../../utils/parserUtils.js';

export class MarkerPacketData extends TBlob implements IMarkerPacketData {
    public marker: string;

    constructor(keyboxData: Uint8Array, dataOffsetInKbx: number, dataLength: number) {
        super(keyboxData, dataOffsetInKbx);

        if (dataLength !== MARKER_PACKET_CONTENT.length) {
            console.warn(`MarkerPacketData: Expected data length ${MARKER_PACKET_CONTENT.length}, got ${dataLength}.`);
        }
        
        const markerBytes = sliceUint8Array(this._kbx, this._blobOffset, this._blobOffset + Math.min(dataLength, MARKER_PACKET_CONTENT.length));
        this.marker = bufferToString(markerBytes, 'utf8');

        if (this.marker !== MARKER_PACKET_CONTENT) {
            console.warn(`MarkerPacketData: Expected content "${MARKER_PACKET_CONTENT}", got "${this.marker}".`);
        }
    }

    public toJSON() {
        return {
            marker: this.marker,
        };
    }
}
