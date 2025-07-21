local skynet = require "skynet"

skynet.register_protocol({
	name = "client",
	id = skynet.PTYPE_CLIENT,
	pack = function(...) return table.concat({...}, "") end,
	unpack = skynet.tostring,
	dispatch = function(session, address, ...)
		skynet.error("dispatch", session, address, ...)
	end
})

skynet.start(function()
	local sinotify = skynet.localname(".sinotify")
	skynet.send(sinotify, "client", "add_watch", "./examples")
end) 
