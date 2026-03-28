/*!
 * PrimeHash v1.0.0
 *
 * An original password hashing scheme that integrates a Keccak-based sponge
 * construction with an adaptive prime-number-based salting mechanism.
 *
 * Author : Alvin Sudarta (NIM: 32220028)
 * Faculty : Technology and Design – Informatics Study Program
 * Inst.  : Universitas Bunda Mulia, Jakarta
 * Year   : 2026
 *
 * Usage (browser / CDN):
 *   const hash   = PrimeHash.hash("mypassword", 24, 32);
 *   const result = PrimeHash.verify("mypassword", 24, hash);
 *
 * Usage (Node.js / CommonJS):
 *   const PrimeHash = require('./primehash');
 */
(function (global, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        global.PrimeHash = factory();
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    /* =========================================================================
     *  CONSTANTS
     * ========================================================================= */

    // Keccak-p(1600, 24) Iota round constants, precomputed as little-endian byte arrays
    const IOTA_BYTES = [
        '0000000000000001', '0000000000008082', '800000000000808A',
        '8000000080008000', '000000000000808B', '0000000080000001',
        '8000000080008081', '8000000000008009', '000000000000008A',
        '0000000000000088', '0000000080008009', '000000008000000A',
        '000000008000808B', '800000000000008B', '8000000000008089',
        '8000000000008003', '8000000000008002', '8000000000000080',
        '000000000000800A', '800000008000000A', '8000000080008081',
        '8000000000008080', '0000000080000001', '8000000080008008',
    ].map(function (h) {
        var b = BigInt('0x' + h);
        var bytes = new Uint8Array(8);
        for (var z = 0; z < 8; z++) bytes[z] = Number((b >> BigInt(z * 8)) & 0xFFn);
        return bytes;
    });

    // Lane rotation offsets for Rho step (5×5 matrix indexed [x][y])
    const RHO_SHIFTS = [
        [0,  36,  3, 41, 18],
        [1,  44, 10, 45,  2],
        [62,  6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39,  8, 14],
    ];

    /* =========================================================================
     *  PRIME NUMBER CACHE
     *  Sieve of Eratosthenes up to 200 000, computed once on first use.
     *  Covers all indices needed by primePosition() (max index ≈ 10001).
     * ========================================================================= */

    var _primes = null;

    function ensurePrimes() {
        if (_primes) return;
        var limit = 200000;
        var sieve = new Uint8Array(limit + 1).fill(1);
        sieve[0] = sieve[1] = 0;
        for (var i = 2; i * i <= limit; i++) {
            if (sieve[i]) {
                for (var j = i * i; j <= limit; j += i) sieve[j] = 0;
            }
        }
        _primes = [];
        for (var k = 2; k <= limit; k++) {
            if (sieve[k]) _primes.push(k);
        }
    }

    function nthPrime(n) {
        ensurePrimes();
        return _primes[n - 1];
    }

    /* =========================================================================
     *  KECCAK PERMUTATION  –  spongeF1600_partial
     *  Byte-level implementation of Theta, Rho+Pi, Chi, and Iota steps.
     *  Matches the PHP reference implementation exactly.
     * ========================================================================= */

    function spongeF1600_partial(state, rounds) {
        // Decode flat 200-byte state into 5×5 lanes of 8 bytes each
        var S = [];
        for (var x = 0; x < 5; x++) {
            S[x] = [];
            for (var y = 0; y < 5; y++) {
                var off = (y * 5 + x) * 8;
                S[x][y] = state.slice(off, off + 8);
            }
        }

        for (var r = 0; r < rounds; r++) {

            // ── Theta ──────────────────────────────────────────────────────────
            var C = [], D = [];
            for (var cx = 0; cx < 5; cx++) {
                C[cx] = new Uint8Array(8);
                D[cx] = new Uint8Array(8);
                for (var cz = 0; cz < 8; cz++) {
                    C[cx][cz] = S[cx][0][cz] ^ S[cx][1][cz] ^ S[cx][2][cz]
                               ^ S[cx][3][cz] ^ S[cx][4][cz];
                }
            }
            for (var dx = 0; dx < 5; dx++) {
                var px = (dx + 4) % 5, nx = (dx + 1) % 5;
                for (var dz = 0; dz < 8; dz++) {
                    var carry = (C[nx][dz] & 0x80) ? 1 : 0;
                    var rot   = ((C[nx][dz] << 1) & 0xFF) | carry;
                    D[dx][dz] = C[px][dz] ^ rot;
                }
            }
            for (var tx = 0; tx < 5; tx++)
                for (var ty = 0; ty < 5; ty++)
                    for (var tz = 0; tz < 8; tz++)
                        S[tx][ty][tz] ^= D[tx][tz];

            // ── Rho + Pi ───────────────────────────────────────────────────────
            var T = [];
            for (var rx = 0; rx < 5; rx++) { T[rx] = []; for (var ry = 0; ry < 5; ry++) T[rx][ry] = new Uint8Array(8); }
            for (var rpx = 0; rpx < 5; rpx++) {
                for (var rpy = 0; rpy < 5; rpy++) {
                    var tnx   = rpy;
                    var tny   = (2 * rpx + 3 * rpy) % 5;
                    var shift = RHO_SHIFTS[rpx][rpy];
                    var bShift = (shift / 8) | 0;
                    var bBit   = shift % 8;
                    for (var rz = 0; rz < 8; rz++) {
                        var src = (rz - bShift + 8) % 8;
                        var cur = S[rpx][rpy][src];
                        var nxt = S[rpx][rpy][(src + 1) % 8];
                        T[tnx][tny][rz] = bBit === 0 ? cur
                            : (((cur << bBit) & 0xFF) | ((nxt >> (8 - bBit)) & 0xFF));
                    }
                }
            }

            // ── Chi ────────────────────────────────────────────────────────────
            var U = [];
            for (var ux = 0; ux < 5; ux++) {
                U[ux] = [];
                for (var uy = 0; uy < 5; uy++) {
                    U[ux][uy] = new Uint8Array(8);
                    for (var uz = 0; uz < 8; uz++) {
                        U[ux][uy][uz] = (T[ux][uy][uz]
                            ^ ((~T[(ux + 1) % 5][uy][uz]) & T[(ux + 2) % 5][uy][uz])) & 0xFF;
                    }
                }
            }

            // ── Iota ───────────────────────────────────────────────────────────
            var rc = IOTA_BYTES[r];
            for (var iz = 0; iz < 8; iz++) U[0][0][iz] ^= rc[iz];

            S = U;
        }

        // Re-encode back to flat 200-byte state
        var result = new Uint8Array(200);
        for (var ey = 0; ey < 5; ey++)
            for (var ex = 0; ex < 5; ex++) {
                var eoff = (ey * 5 + ex) * 8;
                for (var ez = 0; ez < 8; ez++) result[eoff + ez] = S[ex][ey][ez];
            }
        return result;
    }

    /* =========================================================================
     *  SPONGE CONSTRUCTION
     *  rate=8 bits (1 byte), capacity=1592 bits, suffix=0x06 (SHA-3 domain).
     * ========================================================================= */

    function sponge(rate, capacity, inputBytes, suffix, outputLen, rounds) {
        if (rate + capacity !== 1600 || rate % 8 !== 0)
            throw new Error('Invalid rate/capacity combination');

        var rateBytes = rate / 8;
        var state     = new Uint8Array(200);
        var offset    = 0;
        var blockSize = 0;

        // Absorb
        while (offset < inputBytes.length) {
            blockSize = Math.min(inputBytes.length - offset, rateBytes);
            for (var i = 0; i < blockSize; i++) state[i] ^= inputBytes[offset + i];
            offset += blockSize;
            if (blockSize === rateBytes) {
                state = spongeF1600_partial(state, rounds);
                blockSize = 0;
            }
        }

        // Padding (multi-rate padding)
        state[blockSize] ^= suffix;
        if ((suffix & 0x80) !== 0 && blockSize === rateBytes - 1)
            state = spongeF1600_partial(state, rounds);
        state[rateBytes - 1] ^= 0x80;
        state = spongeF1600_partial(state, rounds);

        // Squeeze
        var out = [];
        while (outputLen > 0) {
            blockSize = Math.min(outputLen, rateBytes);
            for (var j = 0; j < blockSize; j++) out.push(state[j]);
            outputLen -= blockSize;
            if (outputLen > 0) state = spongeF1600_partial(state, rounds);
        }
        return new Uint8Array(out);
    }

    /* =========================================================================
     *  UTILITY HELPERS
     * ========================================================================= */

    function bytesToBinStr(bytes) {
        var s = '';
        for (var i = 0; i < bytes.length; i++)
            s += bytes[i].toString(2).padStart(8, '0');
        return s;
    }

    function binStrToBytes(s) {
        var pad = Math.ceil(s.length / 8) * 8;
        s = s.padEnd(pad, '0');
        var out = new Uint8Array(s.length / 8);
        for (var i = 0; i < out.length; i++)
            out[i] = parseInt(s.substring(i * 8, i * 8 + 8), 2);
        return out;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }

    function hexToBytes(hex) {
        var out = new Uint8Array(hex.length / 2);
        for (var i = 0; i < out.length; i++)
            out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    /** Generate a cryptographically random 64-bit salt as a binary string. */
    function saltGenerator() {
        var buf = new Uint8Array(8);
        (typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto).getRandomValues(buf);
        return bytesToBinStr(buf);
    }

    /* =========================================================================
     *  PRIME-POSITION SALTING
     * ========================================================================= */

    /**
     * Derive 64 prime numbers deterministically from the password's ASCII values.
     * Each prime determines one bit-insertion position for the salt.
     */
    function primePosition(password) {
        var vals = [];
        for (var i = 0; i < password.length; i++) vals.push(password.charCodeAt(i) & 0xFF);
        var cur = vals.reduce(function (a, b) { return a + b; }, 0);
        var primes = [];
        for (var k = 0; k < 64; k++) {
            cur += vals[k % vals.length];
            primes.push(nthPrime((cur % 10000) + 2));
        }
        return primes;
    }

    /**
     * Insert 64 salt bits into `data` at positions determined by `primePos`.
     * Positions are computed without sorting, matching the PHP reference exactly.
     *
     * @param {string|Uint8Array} data
     * @param {string}            salt  – 64-character binary string ('0'/'1')
     * @param {number[]}          primePos – array of 64 prime numbers
     * @returns {Uint8Array}
     */
    function salting(data, salt, primePos) {
        var bytes;
        if (typeof data === 'string') {
            bytes = new Uint8Array(data.length);
            for (var i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xFF;
        } else {
            bytes = data;
        }

        var binData   = bytesToBinStr(bytes);
        var totalBits = binData.length + 64;
        var saltPos   = [];

        for (var k = 0; k < 64; k++) {
            var pos = primePos[k] % totalBits;
            while (saltPos.includes(pos)) pos = (pos + 1) % totalBits;
            saltPos.push(pos);
        }

        // Sequential insertion (no pre-sorting) – each insertion shifts subsequent positions
        var result = binData;
        for (var n = 0; n < 64; n++) {
            var p = saltPos[n] + n;
            result = result.slice(0, p) + salt[n] + result.slice(p);
        }

        return binStrToBytes(result);
    }

    /* =========================================================================
     *  PUBLIC API
     * ========================================================================= */

    /**
     * Hash a password using the PrimeHash algorithm.
     *
     * @param  {string} password  – Plaintext password (non-empty)
     * @param  {number} round     – Keccak rounds, 1–24  (recommended: 24)
     * @param  {number} length    – Output length in bytes, 24–99 (recommended: 32)
     * @returns {string}  Hexadecimal hash string (length * 2 hex characters)
     */
    function hash(password, round, length) {
        if (!password)              throw new Error('Password cannot be empty');
        if (length < 24 || length > 99) throw new Error('Length must be between 24 and 99');
        if (round < 1  || round > 24)   throw new Error('Round must be between 1 and 24');

        var salt      = saltGenerator();
        var positions = primePosition(password);
        var saltedPw  = salting(password, salt, positions);
        var hashed    = sponge(8, 1592, saltedPw, 0x06, length - 8, round);
        var withSalt  = salting(hashed, salt, positions);
        return bytesToHex(withSalt);
    }

    /**
     * Verify a plaintext password against a stored PrimeHash.
     *
     * @param  {string} password       – Plaintext password to verify
     * @param  {number} round          – Keccak rounds used during hashing
     * @param  {string} hashedPassword – Stored hex hash to verify against
     * @returns {{ valid: boolean, updateHash: string|null }}
     *          `updateHash` is a fresh hash (for hash rotation) when `valid` is true.
     */
    function verify(password, round, hashedPassword) {
        var lenHex = hashedPassword.length;
        if (lenHex % 2 !== 0)     throw new Error('HashedPassword must have even hex length');
        var lenBytes = lenHex / 2;
        if (lenBytes < 24 || lenBytes > 99) throw new Error('HashedPassword length out of range');

        var lenPwHex  = lenHex - 16;          // 16 hex chars = 8 bytes = 64 bits of stored salt
        var lenPwBit  = lenPwHex * 4;
        var lenPwByte = (lenPwBit / 8) | 0;

        var positions = primePosition(password);

        // Build 64 unique marker characters (A–Z, a–z, 0–9, +, /)
        var markers = [];
        for (var i = 0; i < 26; i++) markers.push(String.fromCharCode(65 + i));
        for (var i = 0; i < 26; i++) markers.push(String.fromCharCode(97 + i));
        for (var i = 0; i < 10; i++) markers.push(String.fromCharCode(48 + i));
        markers.push('+', '/');

        var totalBits    = lenPwBit + 64;
        var saltPos      = [];
        var markerAtPos  = {};

        for (var k = 0; k < 64; k++) {
            var pos = positions[k] % totalBits;
            while (saltPos.includes(pos)) pos = (pos + 1) % totalBits;
            saltPos.push(pos);
            markerAtPos[pos] = markers[k];
        }

        // Reconstruct the marked bitstream to locate where salt bits were inserted
        var marked = '='.repeat(lenPwBit).split('');
        for (var m = 0; m < 64; m++) {
            marked.splice(saltPos[m] + m, 0, markerAtPos[saltPos[m]]);
        }
        var markedStr = marked.join('');

        // Map each marker index → its position in the stored hash binary string
        var hashBin = bytesToBinStr(hexToBytes(hashedPassword));
        var saltMap = {};
        for (var j = 0; j < markedStr.length; j++) {
            var idx = markers.indexOf(markedStr[j]);
            if (idx !== -1) saltMap[idx] = j;
        }

        // Extract the 64 salt bits in original order
        var saltBits = new Array(64).fill('0');
        for (var key in saltMap) {
            var bitPos = saltMap[key];
            if (bitPos < hashBin.length) saltBits[parseInt(key)] = hashBin[bitPos];
        }
        var salt = saltBits.join('');

        // Recompute hash with the extracted salt and compare
        var saltedPw      = salting(password, salt, positions);
        var reHash        = sponge(8, 1592, saltedPw, 0x06, lenPwByte, round);
        var reWithSalt    = salting(reHash, salt, positions);
        var reHex         = bytesToHex(reWithSalt);

        var valid      = reHex === hashedPassword;
        var updateHash = valid ? hash(password, round, lenBytes) : null;

        return { valid: valid, updateHash: updateHash };
    }

    return { hash: hash, verify: verify };
}));
