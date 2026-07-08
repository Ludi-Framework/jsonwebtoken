# Pure Lua — nothing to build. Specs need busted, lint needs luacheck
# (both: luarocks install). `luarocks test` works too.

test:
	busted

lint:
	luacheck jsonwebtoken spec

.PHONY: test lint
