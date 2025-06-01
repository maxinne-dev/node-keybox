
/**
 * Abstract base class for all blob parsing entities.
 * It holds the raw keybox data.
 */
export abstract class TBlob {
    protected _kbx: Uint8Array;
    protected _blobOffset: number; // Offset of this specific blob/structure within the _kbx master array

    protected constructor(keyboxData: Uint8Array, blobOffset: number) {
        this._kbx = keyboxData;
        this._blobOffset = blobOffset;
    }

    /**
     * Gets a subarray of the main keybox data, relative to this blob's/structure's start.
     * @param relativeStart Start offset from the beginning of this blob/structure.
     * @param relativeEnd End offset from the beginning of this blob/structure.
     */
    protected _getRelativeSubarray(relativeStart: number, relativeEnd: number): Uint8Array {
        return this._kbx.subarray(this._blobOffset + relativeStart, this._blobOffset + relativeEnd);
    }
}
    