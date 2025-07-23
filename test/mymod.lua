local skynet = require "skynet"
local mod = {}

local a = 1

local function foobar()
	return a
end

skynet.error("version:", 4)

function mod.foo()
	return foobar
end

function mod.foo2()
	return foobar
end

function mod.foobar(x)
	a = x
end

local meta = {}

meta.__index = meta

function meta:show()
	return "OLD3"
end

function mod.new()
	return setmetatable({}, meta)
end

return mod