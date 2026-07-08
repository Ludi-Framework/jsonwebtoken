local json = require("jsonwebtoken.json")

describe("json.encode", function()
    it("sorts object keys, so equal tables encode identically", function()
        assert.equal('{"alg":"HS256","typ":"JWT"}',
            json.encode({ typ = "JWT", alg = "HS256" }))
    end)

    it("encodes an empty table as an empty object", function()
        assert.equal("{}", json.encode({}))
    end)

    it("encodes sequences as arrays", function()
        assert.equal('["api","web"]', json.encode({ "api", "web" }))
    end)

    it("encodes integers without a decimal point", function()
        assert.equal('{"exp":1516239022}', json.encode({ exp = 1516239022 }))
    end)

    it("encodes floats", function()
        assert.equal("1.5", json.encode(1.5))
    end)

    it("escapes quotes, backslashes and control characters", function()
        local input = 'a"b\\c\nd' .. string.char(0)
        assert.equal('"a\\"b\\\\c\\nd\\u0000"', json.encode(input))
    end)

    it("passes UTF-8 through untouched", function()
        assert.equal('"olá"', json.encode("olá"))
    end)

    it("encodes nested structures", function()
        assert.equal('{"user":{"roles":["admin"],"sub":"42"}}',
            json.encode({ user = { sub = "42", roles = { "admin" } } }))
    end)

    it("rejects values JSON cannot represent", function()
        assert.error_matches(function() json.encode(print) end, "function")
        assert.error_matches(function() json.encode(nil) end, "nil")
        assert.error_matches(function() json.encode(0 / 0) end, "NaN")
        assert.error_matches(function() json.encode(math.huge) end, "NaN")
    end)

    it("rejects non-string object keys", function()
        assert.error_matches(function()
            json.encode({ [1] = "a", x = "b" })
        end, "keys must be strings")
    end)

    it("rejects reference cycles instead of looping forever", function()
        local t = {}
        t.self = t
        assert.error_matches(function() json.encode(t) end, "nesting too deep")
    end)
end)

describe("json.decode", function()
    it("decodes objects, arrays and literals", function()
        local v = json.decode('{"ok":true,"no":false,"list":[1,2,3]}')
        assert.same({ ok = true, no = false, list = { 1, 2, 3 } }, v)
    end)

    it("decodes numbers in every JSON shape", function()
        assert.equal(0, json.decode("0"))
        assert.equal(-42, json.decode("-42"))
        assert.equal(1.5, json.decode("1.5"))
        assert.equal(1e3, json.decode("1e3"))
        assert.equal(-1.25e-2, json.decode("-1.25e-2"))
    end)

    it("decodes escapes, including unicode and surrogate pairs", function()
        assert.equal('a"b\\c\nd', json.decode([["a\"b\\c\nd"]]))
        assert.equal("olá", json.decode([["olá"]]))
        assert.equal("\240\159\152\128", json.decode([["😀"]]))
    end)

    it("maps null to nil", function()
        local v = json.decode('{"gone":null,"kept":1}')
        assert.is_nil(v.gone)
        assert.equal(1, v.kept)
    end)

    it("tolerates whitespace between tokens", function()
        assert.same({ a = 1 }, json.decode(' {\n\t"a" : 1\r} '))
    end)

    it("round-trips what encode produces", function()
        local claims = {
            sub = "1234567890",
            name = "John Doe",
            admin = true,
            iat = 1516239022,
            roles = { "a", "b" },
        }
        assert.same(claims, json.decode(json.encode(claims)))
    end)

    it("rejects trailing characters", function()
        local v, err = json.decode('{"a":1} x')
        assert.is_nil(v)
        assert.matches("Trailing characters", err)
    end)

    it("rejects malformed input with a position", function()
        for _, bad in ipairs({
            '{"a":}', '{"a" 1}', "[1,]", '"unterminated', '"bad \\q escape"',
            "tru", "01x", "-", '{"a":1,}', '{1:2}',
        }) do
            local v, err = json.decode(bad)
            assert.is_nil(v, "accepted: " .. bad)
            assert.matches("position %d+", err)
        end
    end)

    it("rejects raw control characters inside strings", function()
        local v, err = json.decode('"line\nbreak"')
        assert.is_nil(v)
        assert.matches("control character", err)
    end)

    it("rejects unpaired surrogates", function()
        assert.is_nil(json.decode([["\ud800"]]))
        assert.is_nil(json.decode([["\ude00"]]))
    end)
end)
