# Keybox Parser

This is a TypeScript library for parsing GnuPG's keybox (`.kbx`) files. The keybox file format is used by GnuPG to store public keys. This library provides a way to read and parse these files into a structured JavaScript object.

## Installation

To install the necessary dependencies, run:

```bash
npm install
```

## Usage

To use the parser, you can import the `ReadKeybox` function and pass it the path to your `.kbx` file.

```typescript
import ReadKeybox from './src/index.js';

const kbxFilePath = 'path/to/your/key.kbx';

ReadKeybox(kbxFilePath)
  .then(parsedFile => {
    console.log(JSON.stringify(parsedFile, null, 2));
  })
  .catch(error => {
    console.error('Error reading or parsing keybox file:', error);
  });
```

## Building

To build the project, run:

```bash
npm run build
```

This will compile the TypeScript files into JavaScript and output them to the `dist` directory.

## Testing

To run the test suite, use:

```bash
npm test
```

To run the tests with coverage, use:

```bash
npm run coverage
```

## Project Structure

The project is structured as follows:

- `src/`: Contains the TypeScript source code.
  - `index.ts`: The main entry point of the library.
  - `KeyboxParser.ts`: The core parser logic.
  - `models/`: Contains the data models for the different parts of the keybox file format.
  - `__tests__/`: Contains the tests for the library.
- `dist/`: Contains the compiled JavaScript code.
- `package.json`: The project's dependencies and scripts.
- `tsconfig.json`: The TypeScript configuration file.
- `vite.config.ts`: The configuration file for `vitest`.
