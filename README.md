# jsonwebtoken

JSON Web Tokens (RFC 7519) in pure Lua. Zero dependencies.

```lua
local jwt = require("jsonwebtoken")

local token = jwt.sign({ sub = "42", exp = os.time() + 3600 }, secret)

local claims, err = jwt.verify(token, secret)
if claims then
    print(claims.sub) -- "42"
end
```

Three functions — `sign`, `verify`, `decode` — with the SHA-2, base64url
and JSON codecs built in, so `luarocks install jsonwebtoken` is the whole
setup. Tokens are standard compact JWS, interchangeable with
node-jsonwebtoken, jwt.io and every other implementation.

## Installation

```bash
luarocks install jsonwebtoken
```

Works on Lua 5.3+. Pure Lua: no compiler, no OpenSSL, nothing to link.

## Algorithms

HS256 (default), HS384 and HS512 — the HMAC family, where signing and
verifying share one secret. That is exactly the shape of server-issued
session tokens, which is what JWTs are for in most applications.

Asymmetric algorithms (RS256, ES256) need RSA and elliptic-curve
primitives that do not belong in pure Lua; they are out of scope by
design. If you need them, you need a native crypto binding anyway.

## API

### `jwt.sign(claims, secret, opts?) → token`

Signs a claims table and returns the compact token. Claims are signed
exactly as given — nothing is injected — so set `exp` yourself:

```lua
jwt.sign({ sub = "42", exp = os.time() + 3600 }, secret)
jwt.sign(claims, secret, { alg = "HS512" })
jwt.sign(claims, secret, { header = { kid = "key-2" } })
```

`opts.header` adds extra header fields (`kid` being the useful one);
`alg` and `typ` are owned by the library and raise if overridden there.
Encoding is deterministic — object keys are sorted — so the same claims
and secret always produce the same token.

Raises on programmer errors: non-table claims, empty or non-string
secret, unknown algorithm.

### `jwt.verify(token, secret, opts?) → claims | nil, err`

Verifies the signature and the time claims, then returns the claims
table. On failure returns `nil` and an error table:

```lua
local claims, err = jwt.verify(token, secret, {
    leeway = 30,          -- seconds of clock-skew tolerance
    iss = "auth.example", -- also check iss/aud/sub
    aud = "api",
})
if not claims then
    print(err.code, err.message)
end
```

| `err.code` | meaning |
|---|---|
| `malformed` | not three base64url parts of valid JSON |
| `invalid_algorithm` | header `alg` differs from the expected one |
| `invalid_signature` | HMAC does not match |
| `invalid_claim` | `exp`/`nbf` present but not a number |
| `expired` | past `exp` (minus `leeway`) |
| `not_yet_valid` | before `nbf` (plus `leeway`) |
| `invalid_issuer` / `invalid_audience` / `invalid_subject` | claim differs from the option |

`exp` and `nbf` are checked whenever the token carries them; `iss`,
`aud` and `sub` only when the corresponding option is set. `aud`
matches a plain string or membership in an array, per RFC 7519.

### `jwt.decode(token) → claims, header | nil, err`

Decodes **without verifying** — the result is untrusted input until
`verify` has accepted the token. Use it for debugging, or to read the
header (`kid`) and pick which secret to verify with.

## Design notes

- **The algorithm is pinned by the caller, never read from the token.**
  The header is attacker-controlled input; trusting its `alg` is how
  algorithm-confusion attacks work. `verify` expects HS256 unless you
  pass `opts.alg`, and `alg = "none"` does not exist here at all.
- **Signature comparison is constant-time**, so a forger learns nothing
  from how quickly tokens are rejected.
- **The signature is checked before the payload is parsed.** Attacker
  JSON never reaches the decoder.
- **Value-return errors for expected failures.** An expired or forged
  token is normal input for an auth endpoint, not an exception —
  `verify` returns `nil, { code, message }` and the caller branches on
  `code`. Misuse (non-string secret, unknown algorithm) raises.

JWTs carry data, not secrets: the payload is only base64url-encoded,
readable by anyone who holds the token. Put identifiers in claims,
never passwords. For password storage itself, see
[bcryptlua](https://github.com/Ludi-Framework/bcryptlua).

## Development

```bash
make test   # busted specs (luarocks install busted)
make lint   # luacheck (luarocks install luacheck)
```

The specs pin the implementation to NIST SHA-2 vectors, RFC 4231 HMAC
vectors, RFC 4648 base64 vectors and tokens produced by other JWT
implementations.

## License

MIT
