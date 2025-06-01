
// Blob Types
export const BLOB_TYPE_EMPTY = 0;
export const BLOB_TYPE_FIRST = 1;
export const BLOB_TYPE_OPENPGP = 2;
export const BLOB_TYPE_X509 = 3;

// First Blob constants
export const FIRST_BLOB_STRUCTURE_SIZE = 32; // bytes
export const FIRST_BLOB_MAGIC = 'KBXf';
export const FIRST_BLOB_VERSION = 1;

// KeyBlock (OpenPGP/X.509 blob) constants
export const KEY_BLOCK_HEADER_STRUCTURE_SIZE = 20; // bytes for the fixed header part

// KeyInfo constants
export const KEY_INFO_V1_FINGERPRINT_SIZE = 20;
export const KEY_INFO_V2_FINGERPRINT_SIZE = 32;
export const KEY_INFO_V2_KEYGRIP_SIZE = 20;
export const KEY_INFO_V1_MIN_SIZE = 28; // 20(fp) + 4(offsetKeyID) + 2(flags) + 2(RFU)
export const KEY_INFO_V2_MIN_SIZE = 56; // 32(fp) + 2(flags) + 2(RFU) + 20(keygrip)

// UserID Info constants
export const USER_ID_INFO_STRUCTURE_SIZE = 6; // bytes

// UserID constants
export const USER_ID_STRUCTURE_SIZE = 12; // bytes

// Signature Info Block constants
export const SIGNATURE_INFO_BLOCK_STRUCTURE_SIZE = 4; // bytes

// Signature Expiration Time constants
export const SIGNATURE_EXPIRATION_TIME_STRUCTURE_SIZE = 4; // bytes

// Block Trailing Data constants
export const BLOCK_TRAILING_DATA_STRUCTURE_SIZE = 20; // bytes

// Checksum
export const CHECKSUM_SIZE = 20; // bytes (SHA-1 or MD5)

// Public Key Algorithms (RFC 9580 - Section 9.1, Table 18)
export enum PublicKeyAlgorithm {
    RSA_ENCRYPT_SIGN = 1,       // RSA (Encrypt or Sign)
    RSA_ENCRYPT_ONLY = 2,       // RSA Encrypt-Only
    RSA_SIGN_ONLY = 3,          // RSA Sign-Only
    ELGAMAL_ENCRYPT_ONLY = 16,  // Elgamal (Encrypt-Only)
    DSA_SIGN_ONLY = 17,         // DSA (Digital Signature Algorithm)
    ECDH = 18,                  // ECDH public key algorithm
    ECDSA = 19,                 // ECDSA public key algorithm
    // ELGAMAL_ENCRYPT_OR_SIGN = 20, // Reserved (formerly Elgamal Encrypt or Sign)
    // RESERVED_DH_X942 = 21,      // Reserved for Diffie-Hellman (X9.42)
    EDDSA_LEGACY = 22,          // EdDSALegacy (deprecated - used for Ed25519Legacy curve with old OID)
    // RESERVED_AEDH = 23,
    // RESERVED_AEDSA = 24,
    X25519 = 25,                // X25519
    X448 = 26,                  // X448
    ED25519 = 27,               // Ed25519
    ED448 = 28,                 // Ed448
}

// Hash Algorithms (RFC 9580 - Section 9.5, Table 23)
export enum HashAlgorithm {
    // 0 Reserved
    MD5 = 1,        // Deprecated
    SHA1 = 2,       // Deprecated
    RIPEMD160 = 3,  // Deprecated
    // 4-7 Reserved
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
    SHA3_256 = 12,
    // 13 Reserved
    SHA3_512 = 14,
}

// V6 Signature Salt Sizes (RFC 9580 - Section 9.5, Table 23)
export const V6_SIGNATURE_SALT_SIZES: ReadonlyMap<HashAlgorithm, number> = new Map([
    [HashAlgorithm.SHA256, 16],
    [HashAlgorithm.SHA384, 24],
    [HashAlgorithm.SHA512, 32],
    [HashAlgorithm.SHA224, 16],
    [HashAlgorithm.SHA3_256, 16],
    [HashAlgorithm.SHA3_512, 32],
]);


// Symmetric Key Algorithms (RFC 9580 - Section 9.3, Table 21)
export enum SymmetricKeyAlgorithm {
    PLAINTEXT = 0,
    IDEA = 1,        // Deprecated
    TRIPLEDES = 2,   // Deprecated
    CAST5 = 3,       // Deprecated
    BLOWFISH = 4,
    // 5, 6 Reserved
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    TWOFISH = 10,
    CAMELLIA128 = 11,
    CAMELLIA192 = 12,
    CAMELLIA256 = 13,
}


// Packet Tag related
export const PACKET_TAG_MARKER_BIT = 0x80; // Bit 7
export const PACKET_TAG_NEW_FORMAT_BIT = 0x40; // Bit 6
export const PACKET_TAG_TYPE_MASK_NEW_FORMAT = 0x3F; // Bits 0-5 for packet type in new format
export const PACKET_TAG_TYPE_MASK_OLD_FORMAT = 0x3C; // Bits 2-5 for packet type in old format
export const PACKET_TAG_TYPE_SHIFT_OLD_FORMAT = 2;
export const PACKET_TAG_LENGTH_TYPE_MASK_OLD_FORMAT = 0x03; // Bits 0-1 for length type in old format

// Literal Data Packet Format Types (RFC 9580 - Section 5.9)
export enum LiteralDataFormat {
    BINARY = 'b', // 0x62
    TEXT = 't',   // 0x74 (deprecated, interpret as UTF-8)
    UTF8 = 'u',   // 0x75
}
export const LITERAL_FORMAT_BINARY_OCTET = 0x62;
export const LITERAL_FORMAT_TEXT_OCTET = 0x74;
export const LITERAL_FORMAT_UTF8_OCTET = 0x75;


// Marker Packet Content (RFC 9580 - Section 5.8)
export const MARKER_PACKET_CONTENT = "PGP"; // 0x50, 0x47, 0x50

// Compression Algorithms (RFC 9580 - Section 9.4, Table 22)
export enum CompressionAlgorithm {
    UNCOMPRESSED = 0,
    ZIP = 1,    // DEFLATE [RFC1951]
    ZLIB = 2,   // ZLIB [RFC1950]
    BZIP2 = 3,
}

// AEAD Algorithms (RFC 9580 - Section 9.6, Table 25)
export enum AEADAlgorithm {
    // 0 Reserved
    EAX = 1,
    OCB = 2,
    GCM = 3,
}
export const AEAD_AUTH_TAG_LENGTH = 16; // Common for EAX, OCB, GCM (RFC 9580 Sec 5.13.3-5.13.5)

// SEIPD Packet Versions (RFC 9580 - Section 5.13)
export const SEIPD_VERSION_1 = 1;
export const SEIPD_VERSION_2 = 2;

// User Attribute Subpacket Types (RFC 9580 - Section 5.12, Table 13)
export enum UserAttributeSubpacketType {
    // 0 Reserved
    IMAGE = 1,
    // 100-110 Private or Experimental Use
}

// Image Attribute Encoding Format (RFC 9580 - Section 5.12.1, Table 15)
export enum ImageEncodingFormat {
    // 0 Reserved
    JPEG = 1,
    // 100-110 Private or Experimental Use
}

// Signature Types (RFC 9580 - Section 5.2.1, Table 4)
export enum SignatureType {
    BINARY_DOCUMENT = 0x00,
    CANONICAL_TEXT_DOCUMENT = 0x01,
    STANDALONE = 0x02,
    GENERIC_CERTIFICATION = 0x10, // User ID and Public Key Packet
    PERSONA_CERTIFICATION = 0x11, // User ID and Public Key Packet
    CASUAL_CERTIFICATION = 0x12,  // User ID and Public Key Packet
    POSITIVE_CERTIFICATION = 0x13,// User ID and Public Key Packet
    SUBKEY_BINDING = 0x18,
    PRIMARY_KEY_BINDING = 0x19,
    DIRECT_KEY = 0x1F,
    KEY_REVOCATION = 0x20,
    SUBKEY_REVOCATION = 0x28,
    CERTIFICATION_REVOCATION = 0x30,
    TIMESTAMP = 0x40,
    THIRD_PARTY_CONFIRMATION = 0x50,
    RESERVED_FF = 0xFF,
}

// Signature Subpacket Types (RFC 9580 - Section 5.2.3.7, Table 5)
// Using names from RFC or common understanding
export enum SignatureSubpacketType {
    // 0, 1 Reserved
    SIGNATURE_CREATION_TIME = 2,
    SIGNATURE_EXPIRATION_TIME = 3,
    EXPORTABLE_CERTIFICATION = 4,
    TRUST_SIGNATURE = 5,
    REGULAR_EXPRESSION = 6,
    REVOCABLE = 7,
    // 8 Reserved
    KEY_EXPIRATION_TIME = 9,
    PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY = 10, // Placeholder
    PREFERRED_SYMMETRIC_ALGORITHMS_V1_SEIPD = 11,
    REVOCATION_KEY = 12, // Deprecated
    // 13-15 Reserved
    ISSUER_KEY_ID = 16,
    // 17-19 Reserved
    NOTATION_DATA = 20,
    PREFERRED_HASH_ALGORITHMS = 21,
    PREFERRED_COMPRESSION_ALGORITHMS = 22,
    KEY_SERVER_PREFERENCES = 23,
    PREFERRED_KEY_SERVER = 24,
    PRIMARY_USER_ID = 25,
    POLICY_URI = 26,
    KEY_FLAGS = 27,
    SIGNER_USER_ID = 28,
    REASON_FOR_REVOCATION = 29,
    FEATURES = 30,
    SIGNATURE_TARGET = 31,
    EMBEDDED_SIGNATURE = 32,
    ISSUER_FINGERPRINT = 33,
    // 34 Reserved
    INTENDED_RECIPIENT_FINGERPRINT = 35,
    // 37 Reserved (Attested Certifications)
    // 38 Reserved (Key Block)
    PREFERRED_AEAD_CIPHERSUITES = 39,
    // 100-110 Private or Experimental Use
}


// Checksum for SHA-1 in Secret Key Packet S2K usage 254
export const SHA1_CHECKSUM_SIZE = 20;
