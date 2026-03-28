# PrimeHash

An original password hashing scheme integrating a Keccak-based **Sponge Structure** with an adaptive **Built-In Salting** mechanism based on prime numbers. 

No server required — runs entirely in the browser or Node.js with zero dependencies!

## Features
- **Sponge Construction**: Resilient against Length Extension Attacks.
- **Adaptive Prime Salting**: A 64-bit dynamic salt is embedded securely inside the output structure, placed deterministically using a prime number sequence.
- **Zero Dependencies**: Pure Javascript implementation.
- **ISO/IEC 10118-1:2016 Compliant**: Evaluated design for collision and pre-image resistance.

## Quick Start

### 1. Installation

**Using NPM (Node.js)**
```bash
npm install @alvin_sudarta/primehash
```

**Using CDN (Browser)**
```html
<script src="https://cdn.jsdelivr.net/npm/@alvin_sudarta/primehash@1.0.1/primehash.min.js"></script>
```

### 2. API Usage

#### Hash a Password
Generates a new hash with a built-in 64-bit random salt. *You do not need to store the salt separately in your database.*
```javascript
const PrimeHash = require('@alvin_sudarta/primehash');

// PrimeHash.hash(password, round, length)
const hash = PrimeHash.hash("mypassword", 24, 32);
console.log(hash); 
// Output: a 64-character hex string (32 bytes) containing the embedded salt
```

#### Verify a Password
Verifies the plaintext password against the stored hash by reconstructing the prime-based position map and validating the internal salt.
```javascript
// PrimeHash.verify(password, round, storedHash)
const result = PrimeHash.verify("mypassword", 24, hash);

if (result.valid) {
    console.log("Password matches!");
    // Optional (Hash Rotation): Update the stored hash in your database
    // console.log("New hash for rotation:", result.updateHash);
} else {
    console.log("Invalid password!");
}
```

## Parameter Guide

### `hash(password, round, length)`
- `password` *(string)*: The plaintext password to hash. Must not be empty.
- `round` *(number)*: Sponge permutation rounds. Higher = slower & stronger. Recommended: **24**.
- `length` *(number)*: Output length in bytes (24 - 99). The resulting hex string length is `length * 2` characters. Recommended: **32**.

### `verify(password, round, hashedPassword)`
- Returns an object: `{ valid: boolean, updateHash: string | null }`
- `valid` *(boolean)*: `true` if the password matches the hash.
- `updateHash` *(string)*: A freshly generated hash. It is highly recommended to replace the stored hash with this new value on every successful login to mitigate credential-stuffing attacks.

## License
MIT License.

---
*Developed by Alvin Sudarta - Universitas Bunda Mulia (2026)*
