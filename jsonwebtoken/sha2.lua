--- SHA-2 (SHA-256/384/512) and HMAC, pure Lua.
---
--- Needs Lua 5.3+: the implementation is built on native 64-bit
--- integers and bitwise operators. Digests are returned as raw byte
--- strings — JWTs base64url them, nothing here needs hex.

local sha2 = {}

-- FIPS 180-4 constants: fractional parts of the square roots (initial
-- hash values) and cube roots (round constants) of the first primes.

local H256 = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
}

local K256 = {
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
}

local H384 = {
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
}

local H512 = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
}

local K512 = {
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
}

local UNPACK_16x32 = ">" .. ("I4"):rep(16)
local UNPACK_16x64 = ">" .. ("i8"):rep(16)

-- Appends the 0x80 marker, zero padding and the big-endian bit length.
-- The length field is 8 bytes for SHA-256 and 16 for SHA-384/512; a
-- Lua string can never reach 2^61 bytes, so the upper half of a
-- 16-byte field is always zero.
local function pad(msg, block, lenbytes)
    local bits = #msg * 8
    local zeros = (block - (#msg + 1 + lenbytes) % block) % block
    return msg .. "\128" .. ("\0"):rep(zeros + lenbytes - 8) .. string.pack(">I8", bits)
end

local function rotr32(x, n)
    return ((x >> n) | (x << (32 - n))) & 0xffffffff
end

local function rotr64(x, n)
    return (x >> n) | (x << (64 - n))
end

--- SHA-256. Returns the 32-byte digest.
---@param msg string
---@return string digest
function sha2.sha256(msg)
    local h1, h2, h3, h4, h5, h6, h7, h8 = table.unpack(H256)
    msg = pad(msg, 64, 8)
    for off = 1, #msg, 64 do
        local w = { string.unpack(UNPACK_16x32, msg, off) }
        for i = 17, 64 do
            local x, y = w[i - 15], w[i - 2]
            local s0 = rotr32(x, 7) ~ rotr32(x, 18) ~ (x >> 3)
            local s1 = rotr32(y, 17) ~ rotr32(y, 19) ~ (y >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff
        end
        local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
        for i = 1, 64 do
            local s1 = rotr32(e, 6) ~ rotr32(e, 11) ~ rotr32(e, 25)
            local t1 = h + s1 + ((e & f) ~ (~e & g)) + K256[i] + w[i]
            local s0 = rotr32(a, 2) ~ rotr32(a, 13) ~ rotr32(a, 22)
            local t2 = s0 + ((a & b) ~ (a & c) ~ (b & c))
            h, g, f, e = g, f, e, (d + t1) & 0xffffffff
            d, c, b, a = c, b, a, (t1 + t2) & 0xffffffff
        end
        h1, h2, h3, h4 = (h1 + a) & 0xffffffff, (h2 + b) & 0xffffffff, (h3 + c) & 0xffffffff, (h4 + d) & 0xffffffff
        h5, h6, h7, h8 = (h5 + e) & 0xffffffff, (h6 + f) & 0xffffffff, (h7 + g) & 0xffffffff, (h8 + h) & 0xffffffff
    end
    return string.pack(">I4I4I4I4I4I4I4I4", h1, h2, h3, h4, h5, h6, h7, h8)
end

-- SHA-384 and SHA-512 share the compression function and differ only
-- in the initial hash values and how many output words they keep.
-- 64-bit arithmetic needs no masking: Lua integers wrap on overflow.
local function sha512_core(msg, iv, outwords)
    local h1, h2, h3, h4, h5, h6, h7, h8 = table.unpack(iv)
    msg = pad(msg, 128, 16)
    for off = 1, #msg, 128 do
        local w = { string.unpack(UNPACK_16x64, msg, off) }
        for i = 17, 80 do
            local x, y = w[i - 15], w[i - 2]
            local s0 = rotr64(x, 1) ~ rotr64(x, 8) ~ (x >> 7)
            local s1 = rotr64(y, 19) ~ rotr64(y, 61) ~ (y >> 6)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        end
        local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
        for i = 1, 80 do
            local s1 = rotr64(e, 14) ~ rotr64(e, 18) ~ rotr64(e, 41)
            local t1 = h + s1 + ((e & f) ~ (~e & g)) + K512[i] + w[i]
            local s0 = rotr64(a, 28) ~ rotr64(a, 34) ~ rotr64(a, 39)
            local t2 = s0 + ((a & b) ~ (a & c) ~ (b & c))
            h, g, f, e = g, f, e, d + t1
            d, c, b, a = c, b, a, t1 + t2
        end
        h1, h2, h3, h4 = h1 + a, h2 + b, h3 + c, h4 + d
        h5, h6, h7, h8 = h5 + e, h6 + f, h7 + g, h8 + h
    end
    local words = { h1, h2, h3, h4, h5, h6, h7, h8 }
    return string.pack(">" .. ("i8"):rep(outwords), table.unpack(words, 1, outwords))
end

--- SHA-384. Returns the 48-byte digest.
---@param msg string
---@return string digest
function sha2.sha384(msg)
    return sha512_core(msg, H384, 6)
end

--- SHA-512. Returns the 64-byte digest.
---@param msg string
---@return string digest
function sha2.sha512(msg)
    return sha512_core(msg, H512, 8)
end

local HASH = {
    sha256 = { digest = sha2.sha256, block = 64 },
    sha384 = { digest = sha2.sha384, block = 128 },
    sha512 = { digest = sha2.sha512, block = 128 },
}

local function xor_with(key, byte)
    return (key:gsub(".", function(c)
        return string.char(string.byte(c) ~ byte)
    end))
end

--- HMAC (RFC 2104). Returns the raw MAC, as long as the digest.
---@param alg "sha256"|"sha384"|"sha512"
---@param key string any length; longer than a block gets hashed first
---@param msg string
---@return string mac
function sha2.hmac(alg, key, msg)
    local h = HASH[alg]
    if not h then
        error(("Unknown hash %q (sha256, sha384 or sha512)"):format(tostring(alg)), 2)
    end
    if #key > h.block then
        key = h.digest(key)
    end
    key = key .. ("\0"):rep(h.block - #key)
    return h.digest(xor_with(key, 0x5c) .. h.digest(xor_with(key, 0x36) .. msg))
end

return sha2
