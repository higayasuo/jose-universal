# jose-universal
"jose-universal" enables the features of Jose (JWT/JWS/JWE) to be used not only on the web and Node.js, but also in environments like Expo Web/Native and WebView.

## Features

- 🔄 Universal environment support (Node.js, Browser, Expo, WebView)
- 🔐 Full Jose library re-exports (JWT, JWS, JWE)
- 🛡️ Environment detection utilities
- 📦 TypeScript support
- 🧪 Comprehensive testing with Vitest

## Installation

```bash
npm install jose-universal
```

## Usage

```typescript
import {
  jwtVerify,
  SignJWT,
  getEnvironment,
  hasCryptoSupport
} from 'jose-universal'

// Check current environment
const env = getEnvironment() // 'node' | 'browser' | 'expo' | 'webview' | 'unknown'

// Verify crypto support
const hasCrypto = hasCryptoSupport() // boolean

// Use Jose functions as usual
const jwt = await new SignJWT({ sub: 'user123' })
  .setProtectedHeader({ alg: 'HS256' })
  .setIssuedAt()
  .setExpirationTime('2h')
  .sign(new TextEncoder().encode('secret'))
```

## Environment Detection

The library provides utilities to detect the current runtime environment:

```typescript
import {
  isNode,
  isBrowser,
  isExpo,
  isWebView,
  getEnvironment
} from 'jose-universal'

// Individual environment checks
console.log(isNode)     // true in Node.js
console.log(isBrowser)  // true in browsers
console.log(isExpo)     // true in Expo environments
console.log(isWebView)  // true in WebView contexts

// Get current environment
const env = getEnvironment() // Returns the current environment type
```

## API Reference

### Environment Detection

- `isNode: boolean` - True if running in Node.js
- `isBrowser: boolean` - True if running in a browser
- `isExpo: boolean` - True if running in Expo environment
- `isWebView: boolean` - True if running in WebView context
- `getEnvironment(): 'node' | 'browser' | 'expo' | 'webview' | 'unknown'` - Returns current environment
- `hasCryptoSupport(): boolean` - Checks if crypto operations are supported

### Jose Library

All exports from the `jose` library are re-exported. See the [jose documentation](https://github.com/panva/jose) for complete API reference.

## Development

### Prerequisites

- Node.js 18+
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Build the library
npm run build

# Type checking
npm run type-check

# Linting
npm run lint
```

### Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run test` - Run tests in watch mode
- `npm run test:run` - Run tests once
- `npm run test:coverage` - Run tests with coverage
- `npm run type-check` - TypeScript type checking
- `npm run lint` - ESLint linting
- `npm run lint:fix` - ESLint linting with auto-fix

## License

MIT
