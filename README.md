# 🔐 Node Keybox Parser

[![npm version](https://img.shields.io/npm/v/keybox-parser.svg)](https://www.npmjs.com/package/keybox-parser)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-ESM-green.svg)](https://nodejs.org/)
[![Tests](https://img.shields.io/badge/tests-187%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)

> 🚀 A powerful, type-safe TypeScript library for parsing GnuPG Keybox (.kbx) files with comprehensive OpenPGP support

## ✨ Features

- 🔍 **Complete Keybox Parsing** - Parse GnuPG keybox (.kbx) files with full structure analysis
- 🔐 **OpenPGP Support** - Handle all major OpenPGP packet types and algorithms
- 🛡️ **Type Safety** - Comprehensive TypeScript interfaces for all data structures
- ⚡ **Modern Architecture** - Built with ES modules and modern Node.js practices
- 🎯 **Algorithm Support** - RSA, DSA, ECDSA, EdDSA, X25519, X448, Ed25519, Ed448
- ✅ **Checksum Validation** - Automatic integrity verification of parsed data
- 🧪 **Well Tested** - 187 passing tests ensuring reliability
- 📦 **Zero Dependencies** - Lightweight with no external runtime dependencies

## 🚀 Quick Start

### Installation

```bash
npm install keybox-parser
```

### Basic Usage

```typescript
import ReadKeybox from 'keybox-parser';

async function parseKeybox() {
  try {
    // Parse a keybox file
    const keyboxData = await ReadKeybox('/path/to/pubring.kbx');
    
    // Access the parsed structure
    console.log('First Block:', keyboxData.firstBlock);
    console.log('Data Blob:', keyboxData.dataBlob);
    
    // Explore the packets
    if (keyboxData.dataBlob) {
      keyboxData.dataBlob.packets.forEach((packet, index) => {
        console.log(`Packet ${index}:`, packet.tagInfo.packetType);
      });
    }
  } catch (error) {
    console.error('Failed to parse keybox:', error);
  }
}

parseKeybox();
```

## 📋 API Reference

### Main Function

#### `ReadKeybox(kbxFilePath: string): Promise<IKeyboxFile>`

Parses a keybox file and returns the complete structure.

**Parameters:**
- `kbxFilePath` - Path to the .kbx file to parse

**Returns:** `Promise<IKeyboxFile>` - Parsed keybox data structure

### Core Interfaces

#### `IKeyboxFile`
```typescript
interface IKeyboxFile {
  firstBlock: IFirstBlock;
  dataBlob?: {
    header: IKeyBlockHeader;
    metadata: {
      keysInfo: IKeyInfo[];
      userIdInfo: IUserIdInfo;
      userIds: IUserId[];
      signatureInfoBlock: ISignatureInfoBlock;
      signatureExpirationTimes: ISignatureExpirationTime[];
      blockTrailingData: IBlockTrailingData;
    };
    packets: IPacket[];
    checksum: Uint8Array;
    isChecksumValid?: boolean;
  };
}
```

#### `IPacket`
```typescript
interface IPacket {
  tagInfo: IPacketTagInfo;
  totalPacketLength: number;
  dataOffsetInKbx: number;
  packetSpecificData: 
    | IPublicKeyPacketData
    | IUserIDPacketData
    | ISignaturePacketData
    | ITrustPacketData
    | ILiteralPacketData
    | IMarkerPacketData
    | ICompressedDataPacketData
    | IPaddingPacketData
    | ISEIPDData
    | IUserAttributePacketData
    | Uint8Array;
}
```

## 🔧 Supported Features

### 📦 Packet Types
- ✅ Public Key Packets (Type 6)
- ✅ Public Subkey Packets (Type 14)  
- ✅ User ID Packets (Type 13)
- ✅ User Attribute Packets (Type 17)
- ✅ Signature Packets (Type 2)
- ✅ Trust Packets (Type 12)
- ✅ Literal Data Packets (Type 11)
- ✅ Marker Packets (Type 10)
- ✅ Compressed Data Packets (Type 8)
- ✅ SEIPD Packets (Type 18) - v1 & v2
- ✅ Padding Packets (Type 21)

### 🔐 Public Key Algorithms
- ✅ RSA (Encrypt/Sign, Encrypt-Only, Sign-Only)
- ✅ DSA (Digital Signature Algorithm)
- ✅ Elgamal (Encrypt-Only)
- ✅ ECDSA (Elliptic Curve DSA)
- ✅ ECDH (Elliptic Curve Diffie-Hellman)
- ✅ EdDSA Legacy (Ed25519Legacy)
- ✅ X25519 & X448 (Curve25519/448)
- ✅ Ed25519 & Ed448 (EdDSA)

### 🔍 Hash Algorithms
- ✅ SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- ✅ SHA3-256, SHA3-512
- ✅ RIPEMD160, MD5 (legacy support)

## 🏗️ Architecture

The parser follows a modular architecture:

```
┌─────────────────┐
│   ReadKeybox    │  ← Main entry point
└─────────┬───────┘
          │
┌─────────▼───────┐
│  KeyboxParser   │  ← Core parsing engine
└─────────┬───────┘
          │
┌─────────▼───────┐
│    Models       │  ← Data structure models
├─────────────────┤
│ • FirstBlock    │
│ • KeyBlock      │
│ • Packets       │
│ • Signatures    │
│ • UserData      │
└─────────────────┘
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
npm test
```

The project includes 187 tests covering:
- ✅ Parser functionality
- ✅ All packet types
- ✅ Cryptographic algorithms
- ✅ Data structure models
- ✅ Edge cases and error handling

## 🔍 Example: Inspecting Keys

```typescript
import ReadKeybox from 'keybox-parser';
import { PacketTypeEnum, PublicKeyAlgorithm } from 'keybox-parser/types';

async function inspectKeys(kbxPath: string) {
  const keybox = await ReadKeybox(kbxPath);
  
  if (!keybox.dataBlob) {
    console.log('No data blob found');
    return;
  }
  
  console.log(`📊 Keybox Statistics:`);
  console.log(`   Keys: ${keybox.dataBlob.metadata.keysInfo.length}`);
  console.log(`   User IDs: ${keybox.dataBlob.metadata.userIds.length}`);
  console.log(`   Signatures: ${keybox.dataBlob.metadata.signatureInfoBlock.numSignatures}`);
  console.log(`   Packets: ${keybox.dataBlob.packets.length}`);
  console.log(`   Checksum Valid: ${keybox.dataBlob.isChecksumValid ? '✅' : '❌'}`);
  
  // Find public key packets
  const publicKeys = keybox.dataBlob.packets.filter(p => 
    p.tagInfo.packetType === PacketTypeEnum.PUBKEY ||
    p.tagInfo.packetType === PacketTypeEnum.PUBSUBKEY
  );
  
  publicKeys.forEach((keyPacket, index) => {
    const keyData = keyPacket.packetSpecificData as any;
    if (keyData.publicKeyAlgorithm) {
      console.log(`🔑 Key ${index + 1}:`);
      console.log(`   Algorithm: ${PublicKeyAlgorithm[keyData.publicKeyAlgorithm]}`);
      console.log(`   Created: ${keyData.keyCreationDate}`);
    }
  });
}
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **🍴 Fork** the repository
2. **🌿 Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **💾 Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **📤 Push** to the branch (`git push origin feature/amazing-feature`)
5. **🔀 Open** a Pull Request

### Development Setup

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for compatibility with GnuPG keybox format
- Implements OpenPGP specifications (RFC 9580)
- TypeScript-first design for maximum developer experience

---

<div align="center">

**Made with ❤️ for the OpenPGP community**

[Report Bug](https://github.com/maxinne-dev/node-keybox/issues) • [Request Feature](https://github.com/maxinne-dev/node-keybox/issues) • [Documentation](https://github.com/maxinne-dev/node-keybox#readme)

</div>