--- Minimal JSON codec for JWT headers and claim sets.
---
--- Encoding is deterministic — object keys come out sorted — so the
--- same claims always produce byte-identical tokens. Values are what
--- claims need: strings, numbers, booleans and tables. A table whose
--- keys are exactly 1..n encodes as an array, everything else as an
--- object with string keys; the empty table is `{}`.
---
--- Decoding maps `null` to nil, which drops the key from objects.
--- Claim sets never carry a meaningful null, so no sentinel is worth
--- the API noise.

local json = {}

-- Encoding --------------------------------------------------------------

local ESCAPE = {
    ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\f"] = "\\f",
    ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t",
}

local function escape_char(c)
    return ESCAPE[c] or ("\\u%04x"):format(c:byte())
end

local function encode_string(s)
    return '"' .. s:gsub('[\0-\31\\"]', escape_char) .. '"'
end

local function encode_number(n)
    if n ~= n or n == math.huge or n == -math.huge then
        error("Cannot encode NaN or infinity", 0)
    end
    if math.type(n) == "integer" then
        return ("%d"):format(n)
    end
    return ("%.14g"):format(n)
end

local encode_value

local function encode_table(t, depth)
    if depth > 128 then
        error("Cannot encode: nesting too deep (reference cycle?)", 0)
    end
    local total = 0
    for _ in pairs(t) do
        total = total + 1
    end
    if total == 0 then
        return "{}"
    end
    if total == #t then
        local out = {}
        for i = 1, total do
            out[i] = encode_value(t[i], depth)
        end
        return "[" .. table.concat(out, ",") .. "]"
    end
    local keys = {}
    for k in pairs(t) do
        if type(k) ~= "string" then
            error("Cannot encode: object keys must be strings", 0)
        end
        keys[#keys + 1] = k
    end
    table.sort(keys)
    local out = {}
    for i, k in ipairs(keys) do
        out[i] = encode_string(k) .. ":" .. encode_value(t[k], depth)
    end
    return "{" .. table.concat(out, ",") .. "}"
end

encode_value = function(v, depth)
    local t = type(v)
    if t == "string" then
        return encode_string(v)
    elseif t == "number" then
        return encode_number(v)
    elseif t == "boolean" then
        return v and "true" or "false"
    elseif t == "table" then
        return encode_table(v, depth + 1)
    end
    error(("Cannot encode a %s value"):format(t), 0)
end

--- Encodes a value as compact JSON. Raises on values JSON cannot
--- represent (functions, NaN, non-string object keys, cycles).
---@param value string|number|boolean|table
---@return string
function json.encode(value)
    return encode_value(value, 0)
end

-- Decoding --------------------------------------------------------------

local UNESCAPE = {
    ['"'] = '"', ["\\"] = "\\", ["/"] = "/",
    b = "\b", f = "\f", n = "\n", r = "\r", t = "\t",
}

local function fail_at(pos, msg)
    error(("%s at position %d"):format(msg, pos), 0)
end

local function skip_space(s, pos)
    return s:find("[^ \t\r\n]", pos) or #s + 1
end

local decode_value

local function decode_string(s, pos)
    local out = {}
    local i = pos + 1
    while true do
        local c = s:sub(i, i)
        if c == "" then
            fail_at(pos, "Unterminated string")
        elseif c == '"' then
            return table.concat(out), i + 1
        elseif c == "\\" then
            local e = s:sub(i + 1, i + 1)
            if e == "u" then
                local hex = s:match("^%x%x%x%x", i + 2)
                if not hex then
                    fail_at(i, "Malformed unicode escape")
                end
                local cp = tonumber(hex, 16)
                i = i + 6
                if cp >= 0xd800 and cp <= 0xdbff then
                    local lo = s:match("^\\u(%x%x%x%x)", i)
                    lo = lo and tonumber(lo, 16)
                    if not lo or lo < 0xdc00 or lo > 0xdfff then
                        fail_at(i - 6, "Unpaired high surrogate")
                    end
                    cp = 0x10000 + (cp - 0xd800) * 0x400 + (lo - 0xdc00)
                    i = i + 6
                elseif cp >= 0xdc00 and cp <= 0xdfff then
                    fail_at(i - 6, "Unpaired low surrogate")
                end
                out[#out + 1] = utf8.char(cp)
            else
                local u = UNESCAPE[e]
                if not u then
                    fail_at(i, "Invalid escape")
                end
                out[#out + 1] = u
                i = i + 2
            end
        else
            local stop = s:find('["\\]', i)
            local run = s:sub(i, (stop or #s + 1) - 1)
            if run:find("[\0-\31]") then
                fail_at(i, "Raw control character in string")
            end
            out[#out + 1] = run
            i = stop or #s + 1
        end
    end
end

local function decode_number(s, pos)
    local span = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
    local n = span and tonumber(span)
    if not n then
        fail_at(pos, "Malformed number")
    end
    return n, pos + #span
end

local function decode_object(s, pos)
    local obj = {}
    pos = skip_space(s, pos + 1)
    if s:sub(pos, pos) == "}" then
        return obj, pos + 1
    end
    while true do
        if s:sub(pos, pos) ~= '"' then
            fail_at(pos, "Expected a string key")
        end
        local key, val
        key, pos = decode_string(s, pos)
        pos = skip_space(s, pos)
        if s:sub(pos, pos) ~= ":" then
            fail_at(pos, "Expected ':'")
        end
        val, pos = decode_value(s, pos + 1)
        obj[key] = val
        pos = skip_space(s, pos)
        local c = s:sub(pos, pos)
        if c == "}" then
            return obj, pos + 1
        elseif c ~= "," then
            fail_at(pos, "Expected ',' or '}'")
        end
        pos = skip_space(s, pos + 1)
    end
end

local function decode_array(s, pos)
    local arr = {}
    pos = skip_space(s, pos + 1)
    if s:sub(pos, pos) == "]" then
        return arr, pos + 1
    end
    while true do
        local val
        val, pos = decode_value(s, pos)
        arr[#arr + 1] = val
        pos = skip_space(s, pos)
        local c = s:sub(pos, pos)
        if c == "]" then
            return arr, pos + 1
        elseif c ~= "," then
            fail_at(pos, "Expected ',' or ']'")
        end
        pos = pos + 1
    end
end

local function decode_literal(s, pos, word, value)
    if s:sub(pos, pos + #word - 1) ~= word then
        fail_at(pos, "Unexpected character")
    end
    return value, pos + #word
end

decode_value = function(s, pos)
    pos = skip_space(s, pos)
    local c = s:sub(pos, pos)
    if c == "" then
        fail_at(pos, "Unexpected end of input")
    elseif c == '"' then
        return decode_string(s, pos)
    elseif c == "{" then
        return decode_object(s, pos)
    elseif c == "[" then
        return decode_array(s, pos)
    elseif c == "t" then
        return decode_literal(s, pos, "true", true)
    elseif c == "f" then
        return decode_literal(s, pos, "false", false)
    elseif c == "n" then
        return decode_literal(s, pos, "null", nil)
    elseif c == "-" or c:match("%d") then
        return decode_number(s, pos)
    end
    fail_at(pos, "Unexpected character")
end

--- Decodes a JSON string. Returns the value, or nil and a message
--- describing where parsing failed. A top-level `null` also decodes
--- to nil, with no message.
---@param s string
---@return any value
---@return string? err
function json.decode(s)
    if type(s) ~= "string" then
        error("Expected a string to decode", 2)
    end
    local ok, value, pos = pcall(decode_value, s, 1)
    if not ok then
        return nil, tostring(value)
    end
    pos = skip_space(s, pos)
    if pos <= #s then
        return nil, ("Trailing characters at position %d"):format(pos)
    end
    return value
end

return json
