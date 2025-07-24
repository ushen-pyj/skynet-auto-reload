local skynet = require "skynet"
local reload = require "luareload.reload"
local mymod = require "luareload.mymod"


reload.print = function (...)
	-- skynet.error("[reload]", ...)
end

reload.debug = function (...)
	-- skynet.error("[reload debug]", ...)
end

local obj = mymod.new()

local function on_reload(event_path)
	-- 从文件路径中提取模块名
	-- 例如: ./lualib/luareload/mymod.lua -> mymod
	local module_name = string.match(event_path, ".*/([^/]+)%.lua$")
	if not module_name then
		return
	end	
	for name in pairs(package.loaded) do
		local pattern = "%." .. module_name .. "$"
		if string.match(name, pattern) then
			skynet.error("[inotify] reload name:", name)
			skynet.error("reload before", obj:show())
			local ok = reload.reload({ name })
			skynet.error("reload after", ok, obj:show())
		end
	end
end

-- 解析inotify事件的函数
local function parse_inotify_events(msg)
	local events = {}
	if string.sub(msg, 1, 6) == "BATCH:" then
		local header, content = string.match(msg, "^BATCH:(%d+)|(.*)$")
		if header and content then
			local event_count = tonumber(header)
			skynet.error("[inotify] Received batch with", event_count, "events")
			for event_data in string.gmatch(content, "([^;]+)") do
				local event_type, file_path = string.match(event_data, "^([^:]+):(.+)$")
				if event_type and file_path then
					table.insert(events, {
						type = event_type,
						path = file_path
					})
				end
			end
		end
	else
		local event_type, file_path = string.match(msg, "^([^:]+):(.+)$")
		if event_type and file_path then
			table.insert(events, {
				type = event_type,
				path = file_path
			})
		else
			skynet.error("[inotify] Unknown message format:", msg)
		end
	end
	
	return events
end

skynet.register_protocol({
	name = "text",
	id = skynet.PTYPE_TEXT,
	pack = function(...) return table.concat({...}, "") end,
	unpack = skynet.tostring,
})

skynet.register_protocol({
	name = "client",
	id = skynet.PTYPE_CLIENT,
	pack = function(...) return table.concat({...}, "") end,
	unpack = skynet.tostring,
	dispatch = function(session, address, ...)
		local msg = table.concat({...}, "")
		skynet.error("[inotify] Raw message:", msg)
		
		-- 解析inotify事件
		local events = parse_inotify_events(msg)
		
		-- 遍历处理每个事件
		for i, event in ipairs(events) do
			skynet.error(string.format("[inotify] Event %d: %s -> %s", i, event.type, event.path))
			
			-- 在这里可以根据事件类型和路径进行具体的业务处理
			if event.type == "MODIFY" then
				skynet.error("[inotify] File modified:", event.path)
				on_reload(event.path)
				-- 处理文件修改事件
			-- elseif event.type == "CREATE" then
			-- 	skynet.error("[inotify] File created:", event.path)
			-- 	-- 处理文件创建事件
			-- elseif event.type == "DELETE" then
			-- 	skynet.error("[inotify] File deleted:", event.path)
			-- 	-- 处理文件删除事件
			else
				skynet.error("[inotify] Other event:", event.type, event.path)
				-- 处理其他类型事件
			end
		end
		
		skynet.error(string.format("[inotify] Processed %d events", #events))
	end
})

skynet.start(function()
	local sinotify = skynet.localname(".sinotify")
	skynet.send(sinotify, "text", "add_watch", "./lualib/luareload")
end)
