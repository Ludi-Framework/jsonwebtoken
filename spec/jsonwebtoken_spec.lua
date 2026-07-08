local jwt = require("jsonwebtoken")

local SECRET = "your-256-bit-secret"

local CLAIMS = {
    sub = "1234567890",
    name = "John Doe",
    iat = 1516239022,
}

-- Tokens produced by other implementations for CLAIMS and SECRET,
-- with keys in the order our deterministic encoder emits them.
local GOLDEN = {
    HS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        .. ".eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ"
        .. ".fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8",
    HS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"
        .. ".eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ"
        .. ".YnQ0XsGV7q1kSiw8f6Je8F2lnLOGsTbtOs0jJEsVnPhTLs5luClQdnPrdy67ZuWn",
    HS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
        .. ".eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ"
        .. ".P2L-OXlIA6aT5CtEt2UvYwAEXUxxSd3rEfmmCFSflJTZyZaUoQmJ8k68novA-3aL97EWN0q4mqzuxO0KkLnnRA",
}

-- The token from jwt.io's debugger: same claims, same secret, but the
-- payload JSON has a different key order. Verification must accept it,
-- because signatures cover the bytes as received.
local JWT_IO_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    .. ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    .. ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

describe("jwt.sign", function()
    it("produces tokens other implementations produce", function()
        assert.equal(GOLDEN.HS256, jwt.sign(CLAIMS, SECRET))
        assert.equal(GOLDEN.HS384, jwt.sign(CLAIMS, SECRET, { alg = "HS384" }))
        assert.equal(GOLDEN.HS512, jwt.sign(CLAIMS, SECRET, { alg = "HS512" }))
    end)

    it("adds extra header fields such as kid", function()
        local token = jwt.sign(CLAIMS, SECRET, { header = { kid = "key-1" } })
        local _, header = jwt.decode(token)
        assert.equal("key-1", header.kid)
        assert.equal("HS256", header.alg)
        assert.equal("JWT", header.typ)
    end)

    it("refuses to smuggle alg or typ through opts.header", function()
        assert.error_matches(function()
            jwt.sign(CLAIMS, SECRET, { header = { alg = "none" } })
        end, "cannot be overridden")
        assert.error_matches(function()
            jwt.sign(CLAIMS, SECRET, { header = { typ = "X" } })
        end, "cannot be overridden")
    end)

    it("rejects bad arguments loudly", function()
        assert.error_matches(function() jwt.sign("s", SECRET) end,
            "Claims must be a table")
        assert.error_matches(function() jwt.sign(CLAIMS, nil) end,
            "Secret must be a string")
        assert.error_matches(function() jwt.sign(CLAIMS, "") end,
            "Secret must not be empty")
        assert.error_matches(function()
            jwt.sign(CLAIMS, SECRET, { alg = "RS256" })
        end, "Unsupported algorithm")
        assert.error_matches(function()
            jwt.sign(CLAIMS, SECRET, { alg = "none" })
        end, "Unsupported algorithm")
    end)
end)

describe("jwt.verify", function()
    it("round-trips every algorithm", function()
        for _, alg in ipairs({ "HS256", "HS384", "HS512" }) do
            local token = jwt.sign(CLAIMS, SECRET, { alg = alg })
            local claims, err = jwt.verify(token, SECRET, { alg = alg })
            assert.is_nil(err)
            assert.same(CLAIMS, claims)
        end
    end)

    it("accepts a token signed by another implementation", function()
        local claims, err = jwt.verify(JWT_IO_TOKEN, SECRET)
        assert.is_nil(err)
        assert.equal("John Doe", claims.name)
    end)

    it("rejects a wrong secret", function()
        local claims, err = jwt.verify(GOLDEN.HS256, "not-the-secret")
        assert.is_nil(claims)
        assert.equal("invalid_signature", err.code)
    end)

    it("rejects a tampered payload", function()
        local header, _, signature = GOLDEN.HS256:match("([^.]+)%.([^.]+)%.([^.]+)")
        local forged = require("jsonwebtoken.base64url")
            .encode('{"sub":"admin"}')
        local claims, err = jwt.verify(
            header .. "." .. forged .. "." .. signature, SECRET)
        assert.is_nil(claims)
        assert.equal("invalid_signature", err.code)
    end)

    it("pins the algorithm to the caller's choice, not the header's", function()
        local token = jwt.sign(CLAIMS, SECRET, { alg = "HS512" })
        local claims, err = jwt.verify(token, SECRET)
        assert.is_nil(claims)
        assert.equal("invalid_algorithm", err.code)
    end)

    it("rejects alg=none however it is spelled", function()
        local base64url = require("jsonwebtoken.base64url")
        local payload = base64url.encode('{"sub":"admin"}')
        for _, spelling in ipairs({ "none", "None", "NONE" }) do
            local header = base64url.encode(
                ('{"alg":"%s","typ":"JWT"}'):format(spelling))
            local claims, err = jwt.verify(
                header .. "." .. payload .. ".sig", SECRET)
            assert.is_nil(claims)
            assert.equal("invalid_algorithm", err.code)
        end
        -- the classic unsecured-JWT shape ends in a bare dot
        local header = base64url.encode('{"alg":"none","typ":"JWT"}')
        local claims, err = jwt.verify(header .. "." .. payload .. ".", SECRET)
        assert.is_nil(claims)
        assert.equal("malformed", err.code)
    end)

    it("rejects structurally broken tokens as malformed", function()
        for _, bad in ipairs({
            "", "abc", "a.b", "a.b.c.d", "!!!.b.c",
        }) do
            local claims, err = jwt.verify(bad, SECRET)
            assert.is_nil(claims, "accepted: " .. bad)
            assert.equal("malformed", err.code, "on: " .. bad)
        end
    end)

    it("rejects a correctly signed payload that is not JSON", function()
        local base64url = require("jsonwebtoken.base64url")
        local sha2 = require("jsonwebtoken.sha2")
        local header = base64url.encode('{"alg":"HS256","typ":"JWT"}')
        local payload = base64url.encode("not json")
        local signing_input = header .. "." .. payload
        local signature = base64url.encode(
            sha2.hmac("sha256", SECRET, signing_input))
        local claims, err = jwt.verify(
            signing_input .. "." .. signature, SECRET)
        assert.is_nil(claims)
        assert.equal("malformed", err.code)
    end)

    describe("time claims", function()
        local NOW = 1700000000

        it("rejects an expired token", function()
            local token = jwt.sign({ sub = "42", exp = NOW - 10 }, SECRET)
            local claims, err = jwt.verify(token, SECRET, { now = NOW })
            assert.is_nil(claims)
            assert.equal("expired", err.code)
        end)

        it("accepts a token expiring in the future", function()
            local token = jwt.sign({ sub = "42", exp = NOW + 10 }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { now = NOW }))
        end)

        it("treats exp as an exclusive bound, per RFC 7519", function()
            local token = jwt.sign({ sub = "42", exp = NOW }, SECRET)
            local claims, err = jwt.verify(token, SECRET, { now = NOW })
            assert.is_nil(claims)
            assert.equal("expired", err.code)
        end)

        it("applies leeway to exp", function()
            local token = jwt.sign({ sub = "42", exp = NOW - 10 }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { now = NOW, leeway = 30 }))
        end)

        it("rejects a token used before nbf", function()
            local token = jwt.sign({ sub = "42", nbf = NOW + 60 }, SECRET)
            local claims, err = jwt.verify(token, SECRET, { now = NOW })
            assert.is_nil(claims)
            assert.equal("not_yet_valid", err.code)
        end)

        it("applies leeway to nbf", function()
            local token = jwt.sign({ sub = "42", nbf = NOW + 10 }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { now = NOW, leeway = 30 }))
        end)

        it("rejects non-numeric time claims", function()
            for _, claims in ipairs({ { exp = "soon" }, { nbf = "later" } }) do
                local token = jwt.sign(claims, SECRET)
                local decoded, err = jwt.verify(token, SECRET)
                assert.is_nil(decoded)
                assert.equal("invalid_claim", err.code)
            end
        end)

        it("skips time checks when the claims are absent", function()
            assert.truthy(jwt.verify(jwt.sign({ sub = "42" }, SECRET), SECRET))
        end)
    end)

    describe("registered claims", function()
        it("checks iss only when asked", function()
            local token = jwt.sign({ iss = "auth.example" }, SECRET)
            assert.truthy(jwt.verify(token, SECRET))
            assert.truthy(jwt.verify(token, SECRET, { iss = "auth.example" }))
            local claims, err = jwt.verify(token, SECRET, { iss = "other" })
            assert.is_nil(claims)
            assert.equal("invalid_issuer", err.code)
        end)

        it("matches aud as a plain string", function()
            local token = jwt.sign({ aud = "api" }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { aud = "api" }))
            local claims, err = jwt.verify(token, SECRET, { aud = "web" })
            assert.is_nil(claims)
            assert.equal("invalid_audience", err.code)
        end)

        it("matches aud inside an array, per RFC 7519", function()
            local token = jwt.sign({ aud = { "api", "web" } }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { aud = "web" }))
            local claims, err = jwt.verify(token, SECRET, { aud = "mobile" })
            assert.is_nil(claims)
            assert.equal("invalid_audience", err.code)
        end)

        it("fails aud when the claim is missing", function()
            local token = jwt.sign({ sub = "42" }, SECRET)
            local claims, err = jwt.verify(token, SECRET, { aud = "api" })
            assert.is_nil(claims)
            assert.equal("invalid_audience", err.code)
        end)

        it("checks sub only when asked", function()
            local token = jwt.sign({ sub = "42" }, SECRET)
            assert.truthy(jwt.verify(token, SECRET, { sub = "42" }))
            local claims, err = jwt.verify(token, SECRET, { sub = "1" })
            assert.is_nil(claims)
            assert.equal("invalid_subject", err.code)
        end)
    end)
end)

describe("jwt.decode", function()
    it("returns claims and header without a secret", function()
        local claims, header = jwt.decode(GOLDEN.HS256)
        assert.equal("John Doe", claims.name)
        assert.equal("HS256", header.alg)
    end)

    it("does not verify the signature", function()
        local unsigned = GOLDEN.HS256:gsub("%.[^.]+$", ".AAAA")
        local claims = jwt.decode(unsigned)
        assert.equal("John Doe", claims.name)
    end)

    it("returns malformed for garbage", function()
        local claims, err = jwt.decode("not a token")
        assert.is_nil(claims)
        assert.equal("malformed", err.code)
    end)
end)
