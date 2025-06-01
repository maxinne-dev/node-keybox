
import { describe, it, expect } from 'vitest';
import { UserIdPacketData } from '../../../models/packets/UserIdPacketData.js';
import { hexToUint8Array } from '../../test-utils.js';
import { Buffer } from 'buffer';

describe('UserIdPacketData', () => {
    const keyboxData = new Uint8Array(100); // Dummy buffer

    it('should parse a valid User ID packet correctly', () => {
        const userIdString = "Test User <test@example.com>";
        const userIdBytes = Buffer.from(userIdString, 'utf8');
        
        keyboxData.set(userIdBytes, 10); // Store at an offset
        const pkData = new UserIdPacketData(keyboxData, 10, userIdBytes.length);

        expect(pkData.userId).toBe(userIdString);
    });

    it('should handle an empty User ID string', () => {
        const userIdString = "";
        const userIdBytes = Buffer.from(userIdString, 'utf8');
        
        keyboxData.set(userIdBytes, 0);
        const pkData = new UserIdPacketData(keyboxData, 0, userIdBytes.length);

        expect(pkData.userId).toBe("");
    });

    it('should parse UTF-8 characters correctly', () => {
        const userIdString = "Jürgen Müller <jürgen.müller@example.com>";
        const userIdBytes = Buffer.from(userIdString, 'utf8');
        
        keyboxData.set(userIdBytes, 5);
        const pkData = new UserIdPacketData(keyboxData, 5, userIdBytes.length);

        expect(pkData.userId).toBe(userIdString);
    });

    it('should produce correct JSON output', () => {
        const userIdString = "Another User <another@example.org>";
        const userIdBytes = Buffer.from(userIdString, 'utf8');
        
        keyboxData.set(userIdBytes, 0);
        const pkData = new UserIdPacketData(keyboxData, 0, userIdBytes.length);
        const json = pkData.toJSON();

        expect(json.userId).toBe(userIdString);
    });
});
