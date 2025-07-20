#include "skynet.h"
#include "skynet_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

#define MAX_WATCH_DIRS 1024

struct watch_entry {
	char *path;
	int watch_descriptor;
};

struct sinotify_service {
	struct skynet_context * ctx;
	int inotify_fd;
	int socket_id;
	char * watch_path;
	struct watch_entry watch_dirs[MAX_WATCH_DIRS];
	int watch_count;
};

// 前向声明
static int sinotify_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz);
int sinotify_create_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz);
static void handle_sinotify_events(struct sinotify_service *inst, const char *buffer, int length);
static int add_watch_recursive(struct sinotify_service *inst, const char *path);
static int add_single_watch(struct sinotify_service *inst, const char *path);
static void remove_all_watches(struct sinotify_service *inst);

static const char*
get_event_name(uint32_t mask) {
	if (mask & IN_ACCESS) return "ACCESS";
	if (mask & IN_MODIFY) return "MODIFY";
	if (mask & IN_ATTRIB) return "ATTRIB";
	if (mask & IN_CLOSE_WRITE) return "CLOSE_WRITE";
	if (mask & IN_CLOSE_NOWRITE) return "CLOSE_NOWRITE";
	if (mask & IN_OPEN) return "OPEN";
	if (mask & IN_MOVED_FROM) return "MOVED_FROM";
	if (mask & IN_MOVED_TO) return "MOVED_TO";
	if (mask & IN_CREATE) return "CREATE";
	if (mask & IN_DELETE) return "DELETE";
	if (mask & IN_DELETE_SELF) return "DELETE_SELF";
	if (mask & IN_MOVE_SELF) return "MOVE_SELF";
	if (mask & IN_UNMOUNT) return "UNMOUNT";
	if (mask & IN_Q_OVERFLOW) return "Q_OVERFLOW";
	if (mask & IN_IGNORED) return "IGNORED";
	return "UNKNOWN";
}

// 添加单个目录的监听
static int
add_single_watch(struct sinotify_service *inst, const char *path) {
	if (inst->watch_count >= MAX_WATCH_DIRS) {
		skynet_error(inst->ctx, "[sinotify] Maximum watch directories reached (%d)\n", MAX_WATCH_DIRS);
		return -1;
	}
	
	// 检查路径是否已经被监听
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].path && strcmp(inst->watch_dirs[i].path, path) == 0) {
			skynet_error(inst->ctx, "[sinotify] Path %s already being watched (wd=%d)\n", path, inst->watch_dirs[i].watch_descriptor);
			return inst->watch_dirs[i].watch_descriptor;
		}
	}
	
	// 验证路径存在且可访问
	struct stat st;
	if (stat(path, &st) != 0) {
		skynet_error(inst->ctx, "[sinotify] Cannot access path %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	uint32_t mask = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB;
	skynet_error(inst->ctx, "[sinotify] Adding watch for %s with mask 0x%x\n", path, mask);
	
	int wd = inotify_add_watch(inst->inotify_fd, path, mask);
	
	if (wd < 0) {
		skynet_error(inst->ctx, "[sinotify] FAILED to add watch for %s: %s (errno=%d)\n", path, strerror(errno), errno);
		// 检查常见的错误原因
		if (errno == ENOSPC) {
			skynet_error(inst->ctx, "[sinotify] ERROR: inotify watch limit reached. Check /proc/sys/fs/inotify/max_user_watches\n");
		} else if (errno == ENOMEM) {
			skynet_error(inst->ctx, "[sinotify] ERROR: Insufficient memory\n");
		} else if (errno == EACCES) {
			skynet_error(inst->ctx, "[sinotify] ERROR: Permission denied for %s\n", path);
		}
		return -1;
	}
	
	// 保存监听信息
	inst->watch_dirs[inst->watch_count].path = skynet_malloc(strlen(path) + 1);
	strcpy(inst->watch_dirs[inst->watch_count].path, path);
	inst->watch_dirs[inst->watch_count].watch_descriptor = wd;
	inst->watch_count++;
	
	skynet_error(inst->ctx, "[sinotify] SUCCESS: Added watch for %s (wd=%d, total=%d)\n", path, wd, inst->watch_count);
	return wd;
}

// 递归添加目录监听
static int
add_watch_recursive(struct sinotify_service *inst, const char *path) {
	struct stat st;
	if (stat(path, &st) != 0) {
		skynet_error(inst->ctx, "[sinotify] Cannot access %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	if (!S_ISDIR(st.st_mode)) {
		skynet_error(inst->ctx, "[sinotify] %s is not a directory\n", path);
		return -1;
	}
	
	// 添加当前目录的监听
	int wd = add_single_watch(inst, path);
	if (wd < 0) {
		return -1;
	}
	
	// 验证监听是否真正生效
	skynet_error(inst->ctx, "[sinotify] Verifying watch for %s (wd=%d)\n", path, wd);
	
	// 检查inotify系统限制
	char info_buf[256];
	FILE *fp;
	
	// 检查最大监听数量
	fp = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max user watches: %s", info_buf);
		}
		fclose(fp);
	}
	
	// 检查最大队列事件数
	fp = fopen("/proc/sys/fs/inotify/max_queued_events", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max queued events: %s", info_buf);
		}
		fclose(fp);
	}
	
	// 检查最大用户实例数
	fp = fopen("/proc/sys/fs/inotify/max_user_instances", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max user instances: %s", info_buf);
		}
		fclose(fp);
	}
	
	// 遍历子目录
	DIR *dir = opendir(path);
	if (!dir) {
		skynet_error(inst->ctx, "[sinotify] Cannot open directory %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		// 跳过 . 和 .. 
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		// 忽略以点号开头的隐藏文件夹
		if (entry->d_name[0] == '.') {
			continue;
		}
		
		// 构建完整路径
		char full_path[PATH_MAX];
		// 正确处理路径拼接：确保路径以/结尾或在中间添加/
		int path_len = strlen(path);
		if (path_len > 0 && path[path_len - 1] == '/') {
			// 路径已经以/结尾
			snprintf(full_path, sizeof(full_path), "%s%s", path, entry->d_name);
		} else {
			// 路径不以/结尾，需要添加/
			snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
		}
		// 检查是否为目录
		if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
			// 递归添加子目录监听
			add_watch_recursive(inst, full_path);
		}
	}
	
	closedir(dir);
	return 0;
}

// 移除所有监听
static void
remove_all_watches(struct sinotify_service *inst) {
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].watch_descriptor >= 0) {
			inotify_rm_watch(inst->inotify_fd, inst->watch_dirs[i].watch_descriptor);
			skynet_error(inst->ctx, "[sinotify] Removed watch for %s (wd=%d)\n", 
				inst->watch_dirs[i].path, inst->watch_dirs[i].watch_descriptor);
		}
		if (inst->watch_dirs[i].path) {
			skynet_free(inst->watch_dirs[i].path);
			inst->watch_dirs[i].path = NULL;
		}
		inst->watch_dirs[i].watch_descriptor = -1;
	}
	inst->watch_count = 0;
}

// 根据watch descriptor查找对应的路径
static const char*
find_watch_path(struct sinotify_service *inst, int wd) {
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].watch_descriptor == wd) {
			return inst->watch_dirs[i].path;
		}
	}
	return NULL;
}

void
handle_sinotify_events(struct sinotify_service *inst, const char *buffer, int length) {
	if (length <= 0) {
		skynet_error(inst->ctx, "[sinotify] Invalid data length: %d\n", length);
		return;
	}
	int i = 0;
	while (i < length) {
		struct inotify_event *event = (struct inotify_event *) &buffer[i];
		
		// 查找对应的监听路径
		const char *watch_path = find_watch_path(inst, event->wd);
		if (!watch_path) {
			skynet_error(inst->ctx, "[sinotify] Unknown watch descriptor: %d", event->wd);
			i += EVENT_SIZE + event->len;
			continue;
		}
		
		// 构建完整的文件路径
		char full_path[PATH_MAX];
		if (event->len > 0) {
			// 正确处理路径拼接
			int watch_path_len = strlen(watch_path);
			if (watch_path_len > 0 && watch_path[watch_path_len - 1] == '/') {
				// 路径已经以/结尾
				snprintf(full_path, sizeof(full_path), "%s%s", watch_path, event->name);
			} else {
				// 路径不以/结尾，需要添加/
				snprintf(full_path, sizeof(full_path), "%s/%s", watch_path, event->name);
			}
		} else {
			strcpy(full_path, watch_path);
		}
		
		if (event->len > 0) {
			const char* event_name = get_event_name(event->mask);
			skynet_error(inst->ctx, "[sinotify] %s: %s", event_name, event->name);
			
			// 如果创建的是目录，需要添加监听
			if ((event->mask & IN_CREATE) && (event->mask & IN_ISDIR)) {
				skynet_error(inst->ctx, "[sinotify] New directory created, adding recursive watch: %s", full_path);
				add_watch_recursive(inst, full_path);
			}
			// 如果移动到的是目录，需要添加监听
			if ((event->mask & IN_MOVED_TO) && (event->mask & IN_ISDIR)) {
				skynet_error(inst->ctx, "[sinotify] Directory moved in, adding recursive watch: %s", full_path);
				add_watch_recursive(inst, full_path);
			}
		}
		
		i += EVENT_SIZE + event->len;
	}
}

static int
sinotify_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
	// debug 打印消息
	skynet_error(context, "[sinotify] callback type: %d, session: %d, source: %u, sz: %zu", type, session, source, sz);

	struct sinotify_service * inst = ud;
	switch (type) {
	case PTYPE_SOCKET: { // 6
		// Socket消息，处理inotify事件
		struct skynet_socket_message * socket_msg = (struct skynet_socket_message *)msg;
		skynet_error(context, "[sinotify] socket type: %d, id: %d", socket_msg->type, socket_msg->id);
		
		if (socket_msg->id == inst->socket_id) {
			switch (socket_msg->type) {
			case SKYNET_SOCKET_TYPE_CONNECT: // 2
				// inotify文件描述符连接建立，开始监听
				skynet_error(inst->ctx, "[sinotify] socket connected");
				break;
			case SKYNET_SOCKET_TYPE_DATA: // 1
				// inotify文件描述符有数据可读
				skynet_error(inst->ctx, "[sinotify] Received SKYNET_SOCKET_TYPE_DATA message, size=%d", socket_msg->ud);
				
				// 从skynet socket消息中获取inotify数据
				if (socket_msg->buffer && socket_msg->ud > 0) {
					// 处理inotify事件数据
					handle_sinotify_events(inst, socket_msg->buffer, socket_msg->ud);
					// 释放socket消息的buffer
					skynet_free(socket_msg->buffer);
				} else {
					skynet_error(inst->ctx, "[sinotify] No data in socket message");
				}
				break;
			case SKYNET_SOCKET_TYPE_ERROR: // 5
				skynet_error(inst->ctx, "[sinotify] socket error occurred");
				break;
			case SKYNET_SOCKET_TYPE_CLOSE: // 3
				skynet_error(inst->ctx, "[sinotify] socket closed");
				break;
			default:
				skynet_error(inst->ctx, "[sinotify] unknown socket message type: %d", socket_msg->type);
				break;
			}
		}
		break;
	}
	case PTYPE_TEXT:
		// 文本消息，可以用于控制命令
		if (sz > 0) {
			char *cmd = skynet_malloc(sz + 1);
			memcpy(cmd, msg, sz);
			cmd[sz] = '\0';
			
			if (strncmp(cmd, "stop", 4) == 0) {
				skynet_error(context, "[sinotify] Service stopping...");
				// 可以在这里添加停止逻辑
			}else {
				skynet_error(context, "[sinotify] Unknown command: %s (available: stop, status, test)", cmd);
			}
			
			skynet_free(cmd);
		}
		break;
	}
	
	return 0;
}

int
sinotify_service_init(struct sinotify_service * inst, struct skynet_context *ctx, const char * parm) {
	inst->ctx = ctx;
	// 初始化inotify
	inst->inotify_fd = inotify_init();
	if (inst->inotify_fd < 0) {
		skynet_error(ctx, "[sinotify] Failed to initialize inotify: %s", strerror(errno));
		return 1;
	}
	
	// 设置为非阻塞模式
	int flags = fcntl(inst->inotify_fd, F_GETFL, 0);
	if (flags == -1) {
		skynet_error(ctx, "[sinotify] Failed to get inotify flags: %s", strerror(errno));
		close(inst->inotify_fd);
		return 1;
	}
	if (fcntl(inst->inotify_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		skynet_error(ctx, "[sinotify] Failed to set inotify non-blocking: %s", strerror(errno));
		close(inst->inotify_fd);
		return 1;
	}
	
	skynet_error(ctx, "[sinotify] Service initialized successfully");
	
	// 设置要监听的目录
	if (parm && strlen(parm) > 0) {
		inst->watch_path = skynet_malloc(strlen(parm) + 1);
		strcpy(inst->watch_path, parm);
	} else {
		skynet_error(ctx, "[sinotify] No directory specified, using current directory");
		inst->watch_path = skynet_malloc(PATH_MAX);
		if (getcwd(inst->watch_path, PATH_MAX) == NULL) {
			skynet_error(ctx, "[sinotify] Failed to get current directory: %s", strerror(errno));
			return 1;
		}
	}
	
	// 获取绝对路径用于调试
	char *abs_path = realpath(inst->watch_path, NULL);
	if (abs_path) {
		skynet_error(ctx, "[sinotify] Absolute path to watch: %s", abs_path);
		free(abs_path);
	} else {
		skynet_error(ctx, "[sinotify] Warning: cannot resolve absolute path for %s: %s", inst->watch_path, strerror(errno));
	}
	
	// 检查目录是否存在和可访问
	struct stat st;
	if (stat(inst->watch_path, &st) != 0) {
		skynet_error(ctx, "[sinotify] Error: cannot access directory %s: %s", inst->watch_path, strerror(errno));
		return 1;
	}
	if (!S_ISDIR(st.st_mode)) {
		skynet_error(ctx, "[sinotify] Error: %s is not a directory", inst->watch_path);
		return 1;
	}
	
	// 初始化监听数组
	inst->watch_count = 0;
	for (int i = 0; i < MAX_WATCH_DIRS; i++) {
		inst->watch_dirs[i].path = NULL;
		inst->watch_dirs[i].watch_descriptor = -1;
	}
	
	// 检查系统inotify限制
	skynet_error(ctx, "[sinotify] === SYSTEM INOTIFY LIMITS ===\n");
	char info_buf[256];
	FILE *fp;
	
	fp = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
	if (fp && fgets(info_buf, sizeof(info_buf), fp)) {
		skynet_error(ctx, "[sinotify] Max user watches: %s", info_buf);
		fclose(fp);
	}
	
	fp = fopen("/proc/sys/fs/inotify/max_user_instances", "r");
	if (fp && fgets(info_buf, sizeof(info_buf), fp)) {
		skynet_error(ctx, "[sinotify] Max user instances: %s", info_buf);
		fclose(fp);
	}
	
	fp = fopen("/proc/sys/fs/inotify/max_queued_events", "r");
	if (fp && fgets(info_buf, sizeof(info_buf), fp)) {
		skynet_error(ctx, "[sinotify] Max queued events: %s", info_buf);
		fclose(fp);
	}
	skynet_error(ctx, "[sinotify] ================================\n");
	
	// 添加递归监听
	skynet_error(ctx, "[sinotify] Adding recursive watch for %s\n", inst->watch_path);
	if (add_watch_recursive(inst, inst->watch_path) < 0) {
		skynet_error(ctx, "[sinotify] Failed to add recursive watch for %s\n", inst->watch_path);
		return 1;
	}
	skynet_error(ctx, "[sinotify] Started watching directory recursively: %s (total watches=%d)\n", inst->watch_path, inst->watch_count);
	
	// 创建测试文件来验证监听是否工作
	skynet_error(ctx, "[sinotify] Creating test file to verify inotify is working...\n");
	char test_file[PATH_MAX];
	snprintf(test_file, sizeof(test_file), "%s/.inotify_test_%d", inst->watch_path, getpid());
	FILE *test_fp = fopen(test_file, "w");
	if (test_fp) {
		skynet_error(ctx, "[sinotify] Test file created: %s\n", test_file);
		fclose(test_fp);
		skynet_error(ctx, "[sinotify] Test file created: %s\n", test_file);
		// 删除测试文件
		unlink(test_file);
		skynet_error(ctx, "[sinotify] Test file deleted\n");
	} else {
		skynet_error(ctx, "[sinotify] WARNING: Cannot create test file in %s: %s\n", inst->watch_path, strerror(errno));
	}
	
	// 设置回调函数
	skynet_callback(ctx, inst, sinotify_create_cb);
	
	// 将inotify文件描述符绑定到skynet的socket系统
	inst->socket_id = skynet_socket_bind(ctx, inst->inotify_fd);
	if (inst->socket_id < 0) {
		skynet_error(ctx, "[sinotify] Failed to bind inotify fd to skynet socket");
		return 1;
	}
	
	// 启动socket监听
	skynet_socket_start(ctx, inst->socket_id);
	
	skynet_error(ctx, "[sinotify] Service initialized successfully, socket_id=%d", inst->socket_id);
	return 0;
}

// skynet 服务导出函数
int
sinotify_create_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
	struct sinotify_service * inst = (struct sinotify_service *)ud;
	skynet_error(inst->ctx, "[sinotify] callback create\n");
	return sinotify_cb(inst->ctx, inst, type, session, source, msg, sz);
}

void *
sinotify_create(void) {
	struct sinotify_service * inst = skynet_malloc(sizeof(*inst));
	inst->ctx = NULL;
	inst->inotify_fd = -1;
	inst->socket_id = -1;
	inst->watch_path = NULL;
	inst->watch_count = 0;
	for (int i = 0; i < MAX_WATCH_DIRS; i++) {
		inst->watch_dirs[i].path = NULL;
		inst->watch_dirs[i].watch_descriptor = -1;
	}
	skynet_error(inst->ctx, "[sinotify] Service created\n");
	return inst;
}

void
sinotify_release(void * inst) {
	struct sinotify_service * service = (struct sinotify_service *)inst;
	if (service->socket_id >= 0) {
		skynet_socket_close(service->ctx, service->socket_id);
	}
	if (service->inotify_fd >= 0) {
		remove_all_watches(service);
		close(service->inotify_fd);
	}
	skynet_free(service->watch_path);
	skynet_free(service);
}

int
sinotify_init(void * inst, struct skynet_context *ctx, const char * parm) {
	struct sinotify_service * service = (struct sinotify_service *)inst;
	return sinotify_service_init(service, ctx, parm);
}
