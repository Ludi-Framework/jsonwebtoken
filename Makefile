# Pure Lua — nothing to build. Specs need busted, lint needs luacheck
# (both: luarocks install). `luarocks test` works too.

test:
	busted

lint:
	luacheck jsonwebtoken spec

# Format Lua sources in place with stylua.
fmt:
	stylua jsonwebtoken/ spec/

# Verify formatting without writing; fails if anything is out of style.
fmt-check:
	stylua --check jsonwebtoken/ spec/

.PHONY: test lint fmt fmt-check
