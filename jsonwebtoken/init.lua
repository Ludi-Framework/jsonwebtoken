--- JSON Web Tokens (RFC 7519) in pure Lua.
---
--- HMAC algorithms only — HS256, HS384, HS512. Signing and verifying
--- share one secret, which is exactly the shape of server-issued
--- session tokens. Asymmetric algorithms (RS/ES) need RSA and
--- elliptic-curve primitives that belong in a native module, not in
--- pure Lua; they are out of scope by design.

local base64url = require("jsonwebtoken.base64url")
local json = require("jsonwebtoken.json")
local sha2 = require("jsonwebtoken.sha2")

local jwt = {}

local DEFAULT_ALG = "HS256"

local HMAC_HASH = {
    HS256 = "sha256",
    HS384 = "sha384",
    HS512 = "sha512",
}

-- Comparing signatures with `==` leaks how many leading bytes match
-- through timing; accumulate the difference over every byte instead.
local function constant_time_equal(a, b)
    if #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = diff | (a:byte(i) ~ b:byte(i))
    end
    return diff == 0
end

local function fail(code, message)
    return nil, { code = code, message = message }
end

local function checked_alg(opts)
    local alg = opts.alg or DEFAULT_ALG
    if not HMAC_HASH[alg] then
        error(("Unsupported algorithm %q (HS256, HS384 or HS512)"):format(tostring(alg)), 3)
    end
    return alg
end

local function check_secret(secret)
    if type(secret) ~= "string" then
        error("Secret must be a string", 3)
    end
    if secret == "" then
        error("Secret must not be empty", 3)
    end
end

-- RFC 7519 allows `aud` to be a single string or an array of strings.
local function audience_matches(aud, expected)
    if type(aud) == "string" then
        return aud == expected
    end
    if type(aud) == "table" then
        for _, candidate in ipairs(aud) do
            if candidate == expected then
                return true
            end
        end
    end
    return false
end

--- Signs a claims table and returns the compact token.
---
--- Claims are signed as given — nothing is injected. Set `exp`
--- yourself: `{ sub = "42", exp = os.time() + 3600 }`.
---
--- `opts.header` adds extra header fields (`kid` being the useful
--- one); `alg` and `typ` are owned by the library and raise there.
---@param claims table
---@param secret string shared HMAC secret
---@param opts? { alg?: "HS256"|"HS384"|"HS512", header?: table }
---@return string token
function jwt.sign(claims, secret, opts)
    if type(claims) ~= "table" then
        error("Claims must be a table", 2)
    end
    check_secret(secret)
    opts = opts or {}
    local alg = checked_alg(opts)

    local header = { alg = alg, typ = "JWT" }
    if opts.header then
        for k, v in pairs(opts.header) do
            if k == "alg" or k == "typ" then
                error(("%q cannot be overridden through opts.header"):format(k), 2)
            end
            header[k] = v
        end
    end

    local signing_input = base64url.encode(json.encode(header)) .. "." .. base64url.encode(json.encode(claims))
    local signature = sha2.hmac(HMAC_HASH[alg], secret, signing_input)
    return signing_input .. "." .. base64url.encode(signature)
end

--- Verifies a token and returns its claims, or nil and an error table
--- `{ code, message }`. Codes:
---
---   "malformed"          not three base64url parts of valid JSON
---   "invalid_algorithm"  header alg differs from the expected one
---   "invalid_signature"  HMAC does not match
---   "invalid_claim"      exp/nbf present but not a number
---   "expired"            past exp (minus leeway)
---   "not_yet_valid"      before nbf (plus leeway)
---   "invalid_issuer"     iss differs from opts.iss
---   "invalid_audience"   aud does not contain opts.aud
---   "invalid_subject"    sub differs from opts.sub
---
--- The expected algorithm comes from the caller — never from the
--- token header, which is attacker-controlled input. `exp` and `nbf`
--- are checked whenever present; `iss`, `aud` and `sub` only when the
--- corresponding option is set.
---@param token string
---@param secret string shared HMAC secret
---@param opts? { alg?: string, leeway?: number, iss?: string, aud?: string, sub?: string, now?: number }
---@return table|nil claims
---@return { code: string, message: string }? err
function jwt.verify(token, secret, opts)
    if type(token) ~= "string" then
        error("Token must be a string", 2)
    end
    check_secret(secret)
    opts = opts or {}
    local alg = checked_alg(opts)

    local header_b64, claims_b64, signature_b64 = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    if not header_b64 then
        return fail("malformed", "Token is not three dot-separated parts")
    end

    local header_json = base64url.decode(header_b64)
    local header = header_json and json.decode(header_json)
    if type(header) ~= "table" then
        return fail("malformed", "Header is not base64url-encoded JSON")
    end
    if header.alg ~= alg then
        return fail("invalid_algorithm", ("Token is signed with %s, expected %s"):format(tostring(header.alg), alg))
    end

    local signature = base64url.decode(signature_b64)
    if not signature then
        return fail("malformed", "Signature is not valid base64url")
    end
    local expected = sha2.hmac(HMAC_HASH[alg], secret, header_b64 .. "." .. claims_b64)
    if not constant_time_equal(signature, expected) then
        return fail("invalid_signature", "Signature does not match")
    end

    local claims_json = base64url.decode(claims_b64)
    local claims = claims_json and json.decode(claims_json)
    if type(claims) ~= "table" then
        return fail("malformed", "Claims are not base64url-encoded JSON")
    end

    local now = opts.now or os.time()
    local leeway = opts.leeway or 0

    if claims.exp ~= nil then
        if type(claims.exp) ~= "number" then
            return fail("invalid_claim", "exp is not a number")
        end
        if now >= claims.exp + leeway then
            return fail("expired", "Token has expired")
        end
    end
    if claims.nbf ~= nil then
        if type(claims.nbf) ~= "number" then
            return fail("invalid_claim", "nbf is not a number")
        end
        if now < claims.nbf - leeway then
            return fail("not_yet_valid", "Token is not valid yet")
        end
    end

    if opts.iss ~= nil and claims.iss ~= opts.iss then
        return fail("invalid_issuer", ("Issuer is %s, expected %s"):format(tostring(claims.iss), opts.iss))
    end
    if opts.aud ~= nil and not audience_matches(claims.aud, opts.aud) then
        return fail("invalid_audience", ("Audience does not include %s"):format(opts.aud))
    end
    if opts.sub ~= nil and claims.sub ~= opts.sub then
        return fail("invalid_subject", ("Subject is %s, expected %s"):format(tostring(claims.sub), opts.sub))
    end

    return claims
end

--- Decodes a token WITHOUT verifying it. The result is untrusted
--- input until `verify` has accepted the token — use this only for
--- debugging, or to read the header (`kid`) and pick which secret to
--- verify with.
---@param token string
---@return table|nil claims
---@return table? header_or_err header on success, { code, message } on failure
function jwt.decode(token)
    if type(token) ~= "string" then
        error("Token must be a string", 2)
    end
    local header_b64, claims_b64 = token:match("^([^.]+)%.([^.]+)%.[^.]+$")
    if not header_b64 then
        return fail("malformed", "Token is not three dot-separated parts")
    end
    local header_json = base64url.decode(header_b64)
    local header = header_json and json.decode(header_json)
    local claims_json = base64url.decode(claims_b64)
    local claims = claims_json and json.decode(claims_json)
    if type(header) ~= "table" or type(claims) ~= "table" then
        return fail("malformed", "Token parts are not base64url-encoded JSON")
    end
    return claims, header
end

return jwt
