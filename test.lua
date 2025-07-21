local skynet = require "skynet"

-- 解析inotify事件的函数
local function parse_inotify_events(msg)
	local events = {}
	
	-- 检查是否是BATCH格式的消息
	if string.sub(msg, 1, 6) == "BATCH:" then
		-- 解析BATCH格式: "BATCH:数量|事件1:路径1;事件2:路径2;..."
		local header, content = string.match(msg, "^BATCH:(%d+)|(.*)$")
		if header and content then
			local event_count = tonumber(header)
			skynet.error("[inotify] Received batch with", event_count, "events")
			
			-- 分割每个事件
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
		-- 兼容旧格式的单个事件
		local event_type, file_path = string.match(msg, "^([^:]+):(.+)$")
		if event_type and file_path then
			table.insert(events, {
				type = event_type,
				path = file_path
			})
		else
			-- 如果无法解析，记录原始消息
			skynet.error("[inotify] Unknown message format:", msg)
		end
	end
	
	return events
end

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
				-- 处理文件修改事件
			elseif event.type == "CREATE" then
				skynet.error("[inotify] File created:", event.path)
				-- 处理文件创建事件
			elseif event.type == "DELETE" then
				skynet.error("[inotify] File deleted:", event.path)
				-- 处理文件删除事件
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
	skynet.send(sinotify, "client", "add_watch", "./examples")
end)
