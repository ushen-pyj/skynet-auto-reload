# skynet-auto-reload

启动c服务sinotify

具体如何启动这里不多说

lua服务调用add_watch 监听目录, 文件发生变化后会回调到lua服务, 默认忽略.开头的目录

```lua
skynet.send(sinotify, "client", "add_watch", "./test")
```

在示例中, 修改mymod文件:
修改version打印 version: 2
以及show函数 返回 OLD2
文件变化后会打印日志

```lua
[:0100000f] [inotify] Raw message: BATCH:1|MODIFY:./test/mymod.lua;
[:0100000f] [inotify] Received batch with 1 events
[:0100000f] [inotify] Event 1: MODIFY -> ./test/mymod.lua
[:0100000f] [inotify] File modified: ./test/mymod.lua
[:0100000f] [inotify] reload name: luareload.mymod
[:0100000f] reload before OLD1
[:0100000f] version: 2
[:0100000f] reload after true OLD2
[:0100000f] [inotify] Processed 1 events
```