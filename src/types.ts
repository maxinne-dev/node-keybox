
import { PublicKeyAlgorithm } from './constants.js';

export type TCursor = [number, number];

export interface IFirstBlock {
    blobLength: number; // Renamed from kbxTotalLength for clarity: it's length of THIS blob
    blobType: number;
    blobVersion: number;
    headerFlags: number;
    magic: string;
    createdAtTimestamp: number; // Renamed from createdAt
    maintainedAtTimestamp: number; // Renamed from maintainedAt
    readonly structureLength: number; // Fixed structure length (32 bytes)
    createdDate: Date; // Renamed from created
    lastMaintainedDate: Date; // Renamed from lastMaintained
}

export type TRawFirstBlockKeys = Exclude<keyof IFirstBlock, "createdDate" | "lastMaintainedDate" | "structureLength" | "blobLength" | "createdAtTimestamp" | "maintainedAtTimestamp">
  | "rawBlobLength" | "rawCreatedAt" | "rawMaintainedAt";


export interface IKeyBlockHeader {
    blobLength: number;
    type: number;
    version: number;
    blobFlags: number;
    offsetKeyblock: number; // Offset to OpenPGP keyblock or X.509 cert
    lengthKeyblock: number; // Length of the keyblock or cert
    numKeys: number;
    keyInfoSize: number; // Size of EACH key information structure
    readonly structureLength: number; // Fixed header part length (20 bytes)
}

export type TRawKeyBlockHeaderKeys = Exclude<keyof IKeyBlockHeader, "structureLength">;


export interface IKeyInfo {
    keyFlagsRaw: Uint8Array; // Raw bytes for flags
    keyFlagsParsed: { // Example of parsed flags, can be extended
        qualifiedSignature: boolean;
        is32ByteFingerprintInUse?: boolean; // Only for V2
    };
    // V1 specific
    fingerprintV1?: Uint8Array; // 20 bytes
    offsetKeyID?: number;
    // V2 specific
    fingerprintV2?: Uint8Array; // 32 bytes
    keygrip?: Uint8Array; // 20 bytes

    readonly actualSizeInBlob: number; // The keyInfoSize from KeyBlock
}

export interface IUserIdInfo {
    sizeSerialNumber: number;
    numUserIDs: number;
    sizeUserIDInfoStructure: number; // Size of EACH User ID information structure
    readonly structureLength: number; // Fixed structure length (6 bytes)
}

export type TRawUserIdInfoKeys = Exclude<keyof IUserIdInfo, "structureLength">;

export interface IUserId {
    blobOffsetNthUserID: number;
    lengthThisUserID: number;
    uidFlags: number;
    validity: number;
    readonly structureLength: number; // Fixed structure length (12 bytes)
}
export type TRawUserIdKeys = Exclude<keyof IUserId, "structureLength">;


export interface ISignatureInfoBlock {
    numSignatures: number;
    sizeSignatureInfoStructure: number; // Size of EACH signature information structure (usually 4)
    readonly structureLength: number; // Fixed structure length (4 bytes)
}
export type TRawSignatureInfoBlockKeys = Exclude<keyof ISignatureInfoBlock, "structureLength">;


export interface ISignatureExpirationTime {
    expirationTimeRaw: Uint8Array; // Raw 4 bytes
    readonly structureLength: number; // Fixed structure length (4 bytes)
}

export interface IBlockTrailingData {
    ownerTrust: number;
    allValidity: number;
    allValidityParsed?: { // Example for X.509
        keyRevoked?: boolean;
    };
    recheckAfter: number;
    latestTimestamp: number;
    blobCreatedAtTimestamp: number; // Renamed from blobCreatedAt
    blobCreatedAtDate: Date; // Renamed from tsBlobCreatedAt
    sizeReservedSpace: number;
    readonly structureLength: number; // Fixed structure length (20 bytes)
}
export type TRawBlockTrailingDataKeys = Exclude<keyof IBlockTrailingData, "structureLength" | "blobCreatedAtDate" | "allValidityParsed">;

export enum PacketTypeEnum {
    // 0 Reserved
    PKESK = 1, SIG = 2, SKESK = 3, OPS = 4, SECKEY = 5, PUBKEY = 6, SECSUBKEY = 7,
    COMP = 8, SED = 9, MARKER = 10, LIT = 11, TRUST = 12, UID = 13, PUBSUBKEY = 14,
    UAT = 17, SEIPD = 18, 
    // 19 MDC (deprecated, part of SEIPD v1)
    // 20 Reserved
    PADDING = 21,
    // 22-39 Unassigned Critical
    // 40-59 Unassigned Non-Critical
    // 60-63 Private/Experimental
}

export enum LengthTypeEnum {
    OneOctet = 0,
    TwoOctet = 1,
    FourOctet = 2,
    PartialBody = 3, // Changed from "unknown" to match RFC 4880 (indeterminate length for new format)
}

export interface IPacketTagInfo {
    isValidMarker: boolean; // Bit 7 is 1
    isNewFormat: boolean; // Bit 6
    packetType: PacketTypeEnum;
    lengthType?: LengthTypeEnum; // For old format
    actualPacketTypeID: number; // Raw ID from bits
    readonly structureLength: number; // Fixed, 1 byte
}

// ---- Public Key Algorithm Specific Data Structures ----
export interface IRSAPublicKeyParts {
    modulusN: Uint8Array; // MPI for N: n
    publicExponentE: Uint8Array; // MPI for E: e
    bitLengthModN: number;
    bitLengthExpE: number;
    readonly totalLength: number; // Length of these MPIs combined
}

export interface IDSAPublicKeyParts {
    primeP: Uint8Array; // MPI for p
    groupOrderQ: Uint8Array; // MPI for q
    groupGeneratorG: Uint8Array; // MPI for g
    publicKeyY: Uint8Array; // MPI for y
    readonly totalLength: number;
}

export interface IElgamalPublicKeyParts {
    primeP: Uint8Array; // MPI for p
    groupGeneratorG: Uint8Array; // MPI for g
    publicKeyY: Uint8Array; // MPI for y
    readonly totalLength: number;
}

export interface IECDSAPublicKeyParts {
    oid: Uint8Array; // Curve OID
    point: Uint8Array; // MPI of EC public key point
    readonly totalLength: number;
}

export interface IEdDSALegacyPublicKeyParts { // RFC 9580, Algo ID 22
    oid: Uint8Array; // Curve OID
    point: Uint8Array; // MPI of EC public key point (prefixed native form)
    readonly totalLength: number;
}

export interface IKdfParameters {
    hashAlgorithmId: number;
    symmetricAlgorithmId: number;
}

export interface IECDHPublicKeyParts {
    oid: Uint8Array; // Curve OID
    point: Uint8Array; // MPI of EC public key point
    kdfParameters: IKdfParameters; // KDF parameters
    readonly totalLength: number;
}

export interface IX25519PublicKeyParts {
    publicKey: Uint8Array; // 32 octets native public key
    readonly totalLength: number; // Should be 32
}

export interface IX448PublicKeyParts {
    publicKey: Uint8Array; // 56 octets native public key
    readonly totalLength: number; // Should be 56
}

export interface IEd25519PublicKeyParts {
    publicKey: Uint8Array; // 32 octets native public key
    readonly totalLength: number; // Should be 32
}

export interface IEd448PublicKeyParts {
    publicKey: Uint8Array; // 57 octets native public key
    readonly totalLength: number; // Should be 57
}


export type TPublicKeyAlgorithmData =
  | IRSAPublicKeyParts
  | IDSAPublicKeyParts
  | IElgamalPublicKeyParts
  | IECDSAPublicKeyParts
  | IEdDSALegacyPublicKeyParts
  | IECDHPublicKeyParts
  | IX25519PublicKeyParts
  | IX448PublicKeyParts
  | IEd25519PublicKeyParts
  | IEd448PublicKeyParts
  | Uint8Array; // Fallback for unknown/unparsed algorithms

// ---- Signature Algorithm Specific Data Structures ----
export interface IRSASignatureParts {
    signatureMPI: Uint8Array; // m^d mod n
    readonly totalLength: number;
}

export interface IDSASignatureParts { // Also for ECDSA
    r: Uint8Array;
    s: Uint8Array;
    readonly totalLength: number;
}

export interface IEdDSALegacySignatureParts { // Ed25519Legacy
    r_mpi: Uint8Array; // MPI of native R
    s_mpi: Uint8Array; // MPI of native S
    readonly totalLength: number;
}

export interface IEd25519SignatureParts {
    nativeSignature: Uint8Array; // 64 octets
    readonly totalLength: number; // 64
}

export interface IEd448SignatureParts {
    nativeSignature: Uint8Array; // 114 octets
    readonly totalLength: number; // 114
}

export type TSignatureAlgorithmData =
  | IRSASignatureParts
  | IDSASignatureParts
  | IEdDSALegacySignatureParts
  | IEd25519SignatureParts
  | IEd448SignatureParts
  | Uint8Array; // Fallback

// ---- Packet Specific Data Interfaces ----
export interface IPublicKeyPacketData { // Also for Public Subkey Packet (Type 14)
    keyVersion: number; // e.g., 4
    keyCreationTimestamp: number;
    keyCreationDate: Date;
    publicKeyAlgorithm: PublicKeyAlgorithm; // Algorithm ID
    algorithmData: TPublicKeyAlgorithmData;
    // Fingerprint, KeyID can be calculated from this data
}

export interface IUserIDPacketData {
    userId: string; // UTF-8 string
}

export interface ITrustPacketData {
    trustData: Uint8Array; // The actual trust data bytes
}

export interface ILiteralPacketData {
    format: string; // 'b', 't', or 'u' (from LiteralDataFormat enum)
    filename: string;
    timestamp: number; // Unix timestamp
    date: Date;
    literalContent: Uint8Array;
}

export interface IMarkerPacketData {
    marker: string; // Should be "PGP"
}

export interface ICompressedDataPacketData {
    compressionAlgorithm: number; // ID from CompressionAlgorithm enum
    compressedContent: Uint8Array;
}

export interface IPaddingPacketData {
    paddingContent: Uint8Array;
}

export interface ISEIPDDataV1 {
    encryptedDataAndMDC: Uint8Array; // Includes prefix, plaintext, 0xD314, SHA-1 MDC
}

export interface ISEIPDDataV2 {
    cipherAlgorithm: number; // ID from SymmetricKeyAlgorithm enum
    aeadAlgorithm: number; // ID from AEADAlgorithm enum
    chunkSizeOctet: number;
    salt: Uint8Array; // 32 octets
    encryptedDataWithChunkTags: Uint8Array; // All chunks' ciphertexts and their tags
    finalAuthenticationTag: Uint8Array; // For overall message
}

export interface ISEIPDData {
    version: number; // 1 or 2
    data: ISEIPDDataV1 | ISEIPDDataV2;
}

export interface IImageAttributeSubpacketData {
    imageHeaderVersion: number;
    imageEncodingFormat: number; // ID from ImageEncodingFormat enum
    imageData: Uint8Array;
}

export interface IUserAttributeSubpacket {
    subpacketLength: number; // Length of (type + rawData)
    type: number; // UserAttributeSubpacketType ID
    rawData: Uint8Array;
    parsedData?: IImageAttributeSubpacketData | Uint8Array; // Specific parsed data or raw
}

export interface IUserAttributePacketData {
    subpackets: IUserAttributeSubpacket[];
}

export interface ISignatureSubpacket {
    subpacketLength: number; // Length of (type + rawData)
    type: number; // SignatureSubpacketType ID
    isCritical: boolean;
    rawData: Uint8Array;
    // Further parsing of rawData based on type can be added here if needed
}

export interface ISignaturePacketData {
    version: number; // 3, 4, or 6
    signatureType: number; // SignatureType ID
    publicKeyAlgorithm: PublicKeyAlgorithm;
    hashAlgorithm: number; // HashAlgorithm ID
    
    hashedSubpacketsCount?: number; // v4, v6
    hashedSubpackets: ISignatureSubpacket[];
    
    unhashedSubpacketsCount?: number; // v4, v6
    unhashedSubpackets: ISignatureSubpacket[];
    
    left16BitsSignedHash: Uint8Array; // 2 bytes
    
    // v3 specific
    creationTimeV3?: number;
    creationDateV3?: Date;
    signerKeyIDV3?: Uint8Array; // 8 bytes
    
    // v6 specific
    saltV6?: Uint8Array; // Variable length based on hash algo
    
    signatureAlgorithmData: TSignatureAlgorithmData;
}


// Represents the full structure of a parsed packet (header + specific data)
export interface IPacket {
    tagInfo: IPacketTagInfo;
    totalPacketLength: number; // Full length of packet (tag + length-of-length + data)
    dataOffsetInKbx: number; // Absolute offset in KBX file where packet data begins
    packetSpecificData: 
        | IPublicKeyPacketData     // Also for PUBSUBKEY
        | IUserIDPacketData
        | ITrustPacketData
        | ILiteralPacketData
        | IMarkerPacketData
        | ICompressedDataPacketData
        | IPaddingPacketData
        | ISEIPDData
        | IUserAttributePacketData
        | ISignaturePacketData
        | Uint8Array; // Fallback for unknown/unparsed packets
}


export interface IHeaderBlockData {
    keyBlockHeader: IKeyBlockHeader;
    keysInfo: IKeyInfo[];
    userIdInfo: IUserIdInfo;
    userIds: IUserId[];
    signatureInfoBlock: ISignatureInfoBlock;
    signatureExpirationTimes: ISignatureExpirationTime[];
    blockTrailingData: IBlockTrailingData;
}

export interface IKeyboxFile {
    firstBlock: IFirstBlock;
    dataBlob?: { // Assuming one main data blob (OpenPGP or X.509) after FirstBlock
        header: IKeyBlockHeader; // This is the header of the data blob (e.g. OpenPGP blob)
        metadata: { // Metadata stored within this data blob
            keysInfo: IKeyInfo[];
            userIdInfo: IUserIdInfo;
            userIds: IUserId[];
            signatureInfoBlock: ISignatureInfoBlock;
            signatureExpirationTimes: ISignatureExpirationTime[]; // Corrected from sigExpirationTimes
            blockTrailingData: IBlockTrailingData;
        };
        packets: IPacket[]; // Packets from the keyblock/certificate data region
        checksum: Uint8Array; // 20-byte checksum from the end of this blob
        isChecksumValid?: boolean; // True if checksum matches calculated checksum, false otherwise, undefined if not checked/applicable
    };
    // Potentially more blobs if the file contains them
}

// For internal raw data parsing within classes
export type RawFields<T> = Record<keyof T, Uint8Array>;
export type Positions<T> = Record<keyof T, TCursor>;
