# keybox-parser

A Node.js TypeScript library for parsing GnuPG/OpenPGP keybox (.kbx) files.

## Overview

The keybox-parser library provides a comprehensive solution for reading and parsing GnuPG keybox files. It extracts structured information from keybox blobs including OpenPGP packets, key information, user IDs, signatures, and metadata while maintaining full type safety through TypeScript.

## Features

- 🔍 **Complete Keybox Parsing**: Parse first blocks, data blobs, and all associated metadata
- 📦 **OpenPGP Packet Support**: Extract and parse various OpenPGP packet types (public keys, signatures, user IDs, etc.)
- 🔐 **Cryptographic Algorithm Support**: Handle RSA, DSA, ECDSA, EdDSA, and other algorithms
- ✅ **Checksum Validation**: Verify data integrity with SHA-1 checksum validation
- 📝 **Full TypeScript Support**: Complete type definitions for all parsed structures
- 🧪 **Comprehensive Testing**: Extensively tested with 187+ test cases

## Installation

```bash
npm install keybox-parser
```

## Usage

### Basic Usage

```typescript
import ReadKeybox from 'keybox-parser';

async function parseKeyboxFile() {
  try {
    const result = await ReadKeybox('/path/to/keybox.kbx');
    
    // Access first block information
    console.log('Magic:', result.firstBlock.magic);
    console.log('Created:', result.firstBlock.createdDate);
    
    // Access data blob (OpenPGP or X.509)
    if (result.dataBlob) {
      console.log('Blob type:', result.dataBlob.header.type);
      console.log('Number of keys:', result.dataBlob.header.numKeys);
      console.log('Packets found:', result.dataBlob.packets.length);
      
      // Access parsed packets
      result.dataBlob.packets.forEach((packet, index) => {
        console.log(`Packet ${index}:`, packet.tagInfo.packetType);
      });
    }
  } catch (error) {
    console.error('Failed to parse keybox file:', error);
  }
}
```

### Extracting Key Information

```typescript
import ReadKeybox from 'keybox-parser';
import { PacketTypeEnum } from 'keybox-parser/types';

async function extractKeyInfo() {
  const result = await ReadKeybox('/path/to/keybox.kbx');
  
  if (result.dataBlob) {
    // Find public key packets
    const publicKeyPackets = result.dataBlob.packets.filter(
      packet => packet.tagInfo.packetType === PacketTypeEnum.PUBKEY
    );
    
    publicKeyPackets.forEach(packet => {
      const keyData = packet.packetSpecificData as IPublicKeyPacketData;
      console.log('Key algorithm:', keyData.publicKeyAlgorithm);
      console.log('Created:', keyData.keyCreationDate);
    });
    
    // Access user IDs
    result.dataBlob.metadata.userIds.forEach(userId => {
      console.log('User ID flags:', userId.uidFlags);
      console.log('Validity:', userId.validity);
    });
  }
}
```

### Working with Signatures

```typescript
import ReadKeybox from 'keybox-parser';
import { PacketTypeEnum } from 'keybox-parser/types';

async function extractSignatures() {
  const result = await ReadKeybox('/path/to/keybox.kbx');
  
  if (result.dataBlob) {
    const signaturePackets = result.dataBlob.packets.filter(
      packet => packet.tagInfo.packetType === PacketTypeEnum.SIG
    );
    
    signaturePackets.forEach(packet => {
      const sigData = packet.packetSpecificData as ISignaturePacketData;
      console.log('Signature type:', sigData.signatureType);
      console.log('Hash algorithm:', sigData.hashAlgorithm);
      console.log('Hashed subpackets:', sigData.hashedSubpackets.length);
    });
  }
}
```

## API Reference

### Main Function

#### `ReadKeybox(kbxFilePath: string): Promise<IKeyboxFile>`

Reads and parses a keybox file from the specified path.

**Parameters:**
- `kbxFilePath` (string): Path to the .kbx file to parse

**Returns:** Promise resolving to an `IKeyboxFile` object containing the parsed structure

### Key Types

#### `IKeyboxFile`
The main structure representing a parsed keybox file:
- `firstBlock`: First block containing file metadata
- `dataBlob?`: Optional data blob containing OpenPGP or X.509 data

#### `IFirstBlock`
Header information for the keybox file:
- `magic`: Magic string identifying the file format
- `createdDate`: When the file was created
- `lastMaintainedDate`: When the file was last maintained

#### `IDataBlob`
Contains the main keybox data:
- `header`: Key block header with blob metadata
- `metadata`: User IDs, signatures, and other metadata
- `packets`: Array of parsed OpenPGP packets
- `checksum`: File integrity checksum
- `isChecksumValid`: Whether the checksum verification passed

## Supported Packet Types

The library supports parsing the following OpenPGP packet types:

- **Public Key Packets** (PUBKEY, PUBSUBKEY)
- **Signature Packets** (SIG)
- **User ID Packets** (UID)
- **User Attribute Packets** (UAT)
- **Trust Packets** (TRUST)
- **Literal Data Packets** (LIT)
- **Marker Packets** (MARKER)
- **Compressed Data Packets** (COMP)
- **Symmetrically Encrypted Integrity Protected Data** (SEIPD)
- **Padding Packets** (PADDING)

## Cryptographic Algorithm Support

### Public Key Algorithms
- RSA (Encrypt/Sign, Encrypt-Only, Sign-Only)
- DSA (Digital Signature Algorithm)
- ECDSA (Elliptic Curve DSA)
- ECDH (Elliptic Curve Diffie-Hellman)
- EdDSA (Edwards-curve DSA)
- X25519, X448 (Curve25519/448 for encryption)
- Ed25519, Ed448 (Edwards curves for signing)

### Hash Algorithms
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- SHA3-256, SHA3-512
- MD5, RIPEMD-160 (legacy support)

## Development

### Prerequisites
- Node.js 16 or later
- npm or yarn

### Setup

```bash
# Clone the repository
git clone https://github.com/maxinne-dev/node-keybox.git
cd node-keybox

# Install dependencies
npm install

# Run tests
npm test

# Build the project
npm run build

# Run tests with coverage
npm run coverage
```

### Project Structure

```
src/
├── __tests__/          # Test files
├── models/             # Data model classes
├── utils/              # Utility functions
├── constants.ts        # Constants and enums
├── types.ts           # TypeScript type definitions
├── KeyboxParser.ts    # Main parser class
└── index.ts           # Main entry point
```

### Testing

The project uses Vitest for testing with comprehensive coverage:

```bash
# Run all tests
npm test

# Run with coverage report
npm run coverage

# Run specific test file
npx vitest run src/__tests__/specific-test.test.ts
```

## Error Handling

The library provides detailed error messages for common issues:

- **File not found**: When the specified keybox file doesn't exist
- **Invalid format**: When the file doesn't have a valid keybox structure
- **Checksum mismatch**: When data integrity validation fails
- **Parsing errors**: When specific packet or structure parsing fails

Example error handling:

```typescript
try {
  const result = await ReadKeybox('/path/to/keybox.kbx');
  // Process result
} catch (error) {
  if (error.message.includes('ENOENT')) {
    console.error('Keybox file not found');
  } else if (error.message.includes('checksum')) {
    console.error('File integrity check failed');
  } else {
    console.error('Parsing error:', error.message);
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Guidelines

1. Ensure all tests pass before submitting
2. Add tests for new functionality
3. Follow the existing code style
4. Update documentation as needed

## License

This project is private and not yet licensed for public use.

## Credits

Built with TypeScript, tested with Vitest, and designed for robust OpenPGP keybox file parsing.