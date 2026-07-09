--- Unpadded base64url (RFC 4648 §5) — the encoding JWS mandates.

local base64url = {}

local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local ENCODE = {} -- 6-bit value -> character
local DECODE = {} -- character -> 6-bit value
for i = 1, 64 do
    local c = ALPHABET:sub(i, i)
    ENCODE[i - 1] = c
    DECODE[c] = i - 1
end

--- Encodes a byte string. Never emits `=` padding.
---@param s string
---@return string
function base64url.encode(s)
    local out = {}
    local whole = #s - #s % 3
    for i = 1, whole, 3 do
        local a, b, c = s:byte(i, i + 2)
        local v = a << 16 | b << 8 | c
        out[#out + 1] = ENCODE[v >> 18] .. ENCODE[v >> 12 & 63] .. ENCODE[v >> 6 & 63] .. ENCODE[v & 63]
    end
    local rem = #s % 3
    if rem == 1 then
        local a = s:byte(whole + 1)
        out[#out + 1] = ENCODE[a >> 2] .. ENCODE[a << 4 & 63]
    elseif rem == 2 then
        local a, b = s:byte(whole + 1, whole + 2)
        local v = a << 8 | b
        out[#out + 1] = ENCODE[v >> 10] .. ENCODE[v >> 4 & 63] .. ENCODE[v << 2 & 63]
    end
    return table.concat(out)
end

--- Decodes an unpadded base64url string. Returns nil for anything
--- else: `=` padding, whitespace, the standard `+/` alphabet, or a
--- length no unpadded encoding can produce.
---@param s string
---@return string|nil
function base64url.decode(s)
    local rem = #s % 4
    if rem == 1 then
        return nil
    end
    local out = {}
    local whole = #s - rem
    for i = 1, whole, 4 do
        local a, b, c, d =
            DECODE[s:sub(i, i)], DECODE[s:sub(i + 1, i + 1)], DECODE[s:sub(i + 2, i + 2)], DECODE[s:sub(i + 3, i + 3)]
        if not (a and b and c and d) then
            return nil
        end
        local v = a << 18 | b << 12 | c << 6 | d
        out[#out + 1] = string.char(v >> 16, v >> 8 & 255, v & 255)
    end
    if rem == 2 then
        local a, b = DECODE[s:sub(whole + 1, whole + 1)], DECODE[s:sub(whole + 2, whole + 2)]
        if not (a and b) then
            return nil
        end
        out[#out + 1] = string.char(a << 2 | b >> 4)
    elseif rem == 3 then
        local a, b, c =
            DECODE[s:sub(whole + 1, whole + 1)],
            DECODE[s:sub(whole + 2, whole + 2)],
            DECODE[s:sub(whole + 3, whole + 3)]
        if not (a and b and c) then
            return nil
        end
        out[#out + 1] = string.char(a << 2 | b >> 4, (b & 15) << 4 | c >> 2)
    end
    return table.concat(out)
end

return base64url
