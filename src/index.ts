
import * as fs from 'node:fs/promises';
import { IKeyboxFile } from './types.js';
import { KeyboxParser } from './KeyboxParser.js';

export default async function ReadKeybox(kbxFilePath: string): Promise<IKeyboxFile> {
    const kbxUint8Array = await fs.readFile(kbxFilePath).then(data => Uint8Array.from(data));
    const parser = new KeyboxParser(kbxUint8Array);
    const parsedFile = parser.parse();
    
    // For debugging purposes, you can log the prettified structure:
    // console.log(JSON.stringify(parsedFile, (key, value) => {
    //     if (value instanceof Uint8Array) {
    //         // Use bufferToHexString if it's added to utils
    //         return Buffer.from(value).toString('hex');
    //     }
    //     if (value && typeof value.toJSON === 'function') {
    //        // Pass kbxUint8Array if needed by specific toJSON, e.g., UserId.toJSON(kbxUint8Array)
    //        // For now, KeyboxParser holds kbxUint8Array, so models could potentially access it via parser instance if refactored
    //        if (key === 'userIds' && Array.isArray(value)) {
    //             return value.map(uid => uid.toJSON(kbxUint8Array));
    //        }
    //        return value.toJSON();
    //     }
    //     return value;
    // }, 2));

    return parsedFile;
}
