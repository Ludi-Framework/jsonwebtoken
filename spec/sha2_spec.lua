local sha2 = require("jsonwebtoken.sha2")

local function hex(s)
    return (s:gsub(".", function(c)
        return ("%02x"):format(c:byte())
    end))
end

-- FIPS 180-4 / NIST CAVP vectors.
local VECTORS = {
    {
        msg = "",
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            .. "274edebfe76f65fbd51ad2f14898b95b",
        sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            .. "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    {
        msg = "abc",
        sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        sha384 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            .. "8086072ba1e7cc2358baeca134c825a7",
        sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            .. "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
    {
        -- crosses one block boundary
        msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        sha256 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        sha384 = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
            .. "b0455a8520bc4e6f5fe95b1fe3c8452b",
        sha512 = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
            .. "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
    },
    {
        msg = ("a"):rep(1000000),
        label = "one million 'a'",
        sha256 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        sha384 = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
            .. "07b8b3dc38ecc4ebae97ddd87f3d8985",
        sha512 = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            .. "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    },
}

for _, algorithm in ipairs({ "sha256", "sha384", "sha512" }) do
    describe("sha2." .. algorithm, function()
        for _, v in ipairs(VECTORS) do
            local label = v.label or ("%q"):format(v.msg:sub(1, 16))
            it("matches the NIST vector for " .. label, function()
                assert.equal(v[algorithm], hex(sha2[algorithm](v.msg)))
            end)
        end
    end)
end

describe("sha2 padding boundaries", function()
    -- Lengths around the point where the length field forces an extra
    -- block: 55/56 for SHA-256 (64-byte blocks), 111/112 for SHA-512.
    it("hashes messages of every length up to two blocks consistently", function()
        for len = 0, 130 do
            local msg = ("x"):rep(len)
            assert.equal(32, #sha2.sha256(msg))
            assert.equal(48, #sha2.sha384(msg))
            assert.equal(64, #sha2.sha512(msg))
        end
    end)
end)

-- RFC 4231 test cases 1, 2 and 6 (the last exercises a key longer
-- than the block size, which must be hashed down first).
local HMAC_VECTORS = {
    {
        label = "20-byte key",
        key = ("\11"):rep(20),
        msg = "Hi There",
        sha256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        sha384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
            .. "faea9ea9076ede7f4af152e8b2fa9cb6",
        sha512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            .. "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    {
        label = "short text key",
        key = "Jefe",
        msg = "what do ya want for nothing?",
        sha256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        sha384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
            .. "8e2240ca5e69e2c78b3239ecfab21649",
        sha512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            .. "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    {
        label = "131-byte key (longer than the block)",
        key = ("\170"):rep(131),
        msg = "Test Using Larger Than Block-Size Key - Hash Key First",
        sha256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        sha384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
            .. "0c2ef6ab4030fe8296248df163f44952",
        sha512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            .. "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
}

describe("sha2.hmac", function()
    for _, hash in ipairs({ "sha256", "sha384", "sha512" }) do
        for _, v in ipairs(HMAC_VECTORS) do
            it(("matches RFC 4231 for %s with a %s"):format(hash, v.label), function()
                assert.equal(v[hash], hex(sha2.hmac(hash, v.key, v.msg)))
            end)
        end
    end

    it("rejects an unknown hash name", function()
        assert.error_matches(function()
            sha2.hmac("md5", "key", "msg")
        end, "Unknown hash")
    end)
end)
