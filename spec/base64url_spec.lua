local base64url = require("jsonwebtoken.base64url")

describe("base64url.encode", function()
    -- RFC 4648 §10 vectors, padding stripped.
    local VECTORS = {
        { "", "" },
        { "f", "Zg" },
        { "fo", "Zm8" },
        { "foo", "Zm9v" },
        { "foob", "Zm9vYg" },
        { "fooba", "Zm9vYmE" },
        { "foobar", "Zm9vYmFy" },
    }

    for _, v in ipairs(VECTORS) do
        it(("encodes %q as %q"):format(v[1], v[2]), function()
            assert.equal(v[2], base64url.encode(v[1]))
        end)
    end

    it("uses - and _ instead of + and /", function()
        assert.equal("-_8", base64url.encode("\251\255"))
    end)

    it("never emits padding", function()
        for len = 0, 12 do
            assert.is_nil(base64url.encode(("x"):rep(len)):find("=", 1, true))
        end
    end)
end)

describe("base64url.decode", function()
    it("round-trips every byte value", function()
        local all = {}
        for b = 0, 255 do
            all[#all + 1] = string.char(b)
        end
        local blob = table.concat(all)
        assert.equal(blob, base64url.decode(base64url.encode(blob)))
    end)

    it("round-trips every remainder length", function()
        for len = 0, 9 do
            local s = ("\0\255x"):rep(4):sub(1, len)
            assert.equal(s, base64url.decode(base64url.encode(s)))
        end
    end)

    it("decodes a real JWT header", function()
        assert.equal('{"alg":"HS256","typ":"JWT"}', base64url.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))
    end)

    it("rejects padded input", function()
        assert.is_nil(base64url.decode("Zg=="))
    end)

    it("rejects the standard +/ alphabet", function()
        assert.is_nil(base64url.decode("+w"))
        assert.is_nil(base64url.decode("/w"))
    end)

    it("rejects whitespace", function()
        assert.is_nil(base64url.decode("Zm9v\n"))
        assert.is_nil(base64url.decode("Zm 9v"))
    end)

    it("rejects a length no encoding produces", function()
        assert.is_nil(base64url.decode("Zm9vX"))
    end)
end)
