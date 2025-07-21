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
#define MAX_SERVICE_ADDRS 32 

struct watch_entry {
	char *path;
	int watch_descriptor;
	uint32_t service_addrs[MAX_SERVICE_ADDRS]; 
	int service_count;
};

struct sinotify_service {
	struct skynet_context * ctx;
	int inotify_fd;
	int socket_id;
	char * watch_path;
	struct watch_entry watch_dirs[MAX_WATCH_DIRS];
	int watch_count;
};

static int sinotify_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz);
static void handle_sinotify_events(struct sinotify_service *inst, const char *buffer, int length);
static int add_watch_recursive(struct sinotify_service *inst, const char *path);
static int add_single_watch(struct sinotify_service *inst, const char *path);
static int add_single_watch_with_callback(struct sinotify_service *inst, const char *path, uint32_t service_addr);
static void remove_all_watches(struct sinotify_service *inst);
static int remove_service_from_watch(struct sinotify_service *inst, uint32_t service_addr);
static void cleanup_empty_watches(struct sinotify_service *inst);

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

static int
add_single_watch(struct sinotify_service *inst, const char *path) {
	return add_single_watch_with_callback(inst, path, 0);
}

static int
add_single_watch_with_callback(struct sinotify_service *inst, const char *path, uint32_t service_addr) {
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].path && strcmp(inst->watch_dirs[i].path, path) == 0) {
			skynet_error(inst->ctx, "[sinotify] Path %s already being watched (wd=%d)\n", path, inst->watch_dirs[i].watch_descriptor);
			for (int j = 0; j < inst->watch_dirs[i].service_count; j++) {
				if (inst->watch_dirs[i].service_addrs[j] == service_addr) {
					skynet_error(inst->ctx, "[sinotify] Service %u already registered for path %s\n", service_addr, path);
					return inst->watch_dirs[i].watch_descriptor;
				}
			}
			
			if (inst->watch_dirs[i].service_count < MAX_SERVICE_ADDRS) {
				inst->watch_dirs[i].service_addrs[inst->watch_dirs[i].service_count] = service_addr;
				inst->watch_dirs[i].service_count++;
				skynet_error(inst->ctx, "[sinotify] Added service %u to existing watch for path %s (total services: %d)\n", 
					service_addr, path, inst->watch_dirs[i].service_count);
			} else {
				skynet_error(inst->ctx, "[sinotify] Maximum service addresses reached for path %s\n", path);
			}
			return inst->watch_dirs[i].watch_descriptor;
		}
	}
	
	if (inst->watch_count >= MAX_WATCH_DIRS) {
		skynet_error(inst->ctx, "[sinotify] Maximum watch directories reached (%d)\n", MAX_WATCH_DIRS);
		return -1;
	}
	struct stat st;
	if (stat(path, &st) != 0) {
		skynet_error(inst->ctx, "[sinotify] Cannot access path %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	uint32_t mask = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
	skynet_error(inst->ctx, "[sinotify] Adding watch for %s with mask 0x%x\n", path, mask);
	
	int wd = inotify_add_watch(inst->inotify_fd, path, mask);
	
	if (wd < 0) {
		skynet_error(inst->ctx, "[sinotify] FAILED to add watch for %s: %s (errno=%d)\n", path, strerror(errno), errno);
		if (errno == ENOSPC) {
			skynet_error(inst->ctx, "[sinotify] ERROR: inotify watch limit reached. Check /proc/sys/fs/inotify/max_user_watches\n");
		} else if (errno == ENOMEM) {
			skynet_error(inst->ctx, "[sinotify] ERROR: Insufficient memory\n");
		} else if (errno == EACCES) {
			skynet_error(inst->ctx, "[sinotify] ERROR: Permission denied for %s\n", path);
		}
		return -1;
	}
	
	inst->watch_dirs[inst->watch_count].path = skynet_malloc(strlen(path) + 1);
	strcpy(inst->watch_dirs[inst->watch_count].path, path);
	inst->watch_dirs[inst->watch_count].watch_descriptor = wd;
	
	for (int i = 0; i < MAX_SERVICE_ADDRS; i++) {
		inst->watch_dirs[inst->watch_count].service_addrs[i] = 0;
	}
	inst->watch_dirs[inst->watch_count].service_addrs[0] = service_addr;
	inst->watch_dirs[inst->watch_count].service_count = (service_addr != 0) ? 1 : 0;
	inst->watch_count++;
	
	skynet_error(inst->ctx, "[sinotify] SUCCESS: Added watch for %s (wd=%d, total=%d)\n", path, wd, inst->watch_count);
	return wd;
}

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
	
	int wd = add_single_watch(inst, path);
	if (wd < 0) {
		return -1;
	}
	
	skynet_error(inst->ctx, "[sinotify] Verifying watch for %s (wd=%d)\n", path, wd);
	
	char info_buf[256];
	FILE *fp;
	
	fp = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max user watches: %s", info_buf);
		}
		fclose(fp);
	}
	
	fp = fopen("/proc/sys/fs/inotify/max_queued_events", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max queued events: %s", info_buf);
		}
		fclose(fp);
	}
	
	fp = fopen("/proc/sys/fs/inotify/max_user_instances", "r");
	if (fp) {
		if (fgets(info_buf, sizeof(info_buf), fp)) {
			skynet_error(inst->ctx, "[sinotify] Max user instances: %s", info_buf);
		}
		fclose(fp);
	}
	
	DIR *dir = opendir(path);
	if (!dir) {
		skynet_error(inst->ctx, "[sinotify] Cannot open directory %s: %s\n", path, strerror(errno));
		return -1;
	}
	
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		if (entry->d_name[0] == '.') {
			continue;
		}
		
		char full_path[PATH_MAX];
		int path_len = strlen(path);
		if (path_len > 0 && path[path_len - 1] == '/') {
			snprintf(full_path, sizeof(full_path), "%s%s", path, entry->d_name);
		} else {
			snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
		}
		if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
			add_watch_recursive(inst, full_path);
		}
	}
	
	closedir(dir);
	return 0;
}

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
		for (int j = 0; j < MAX_SERVICE_ADDRS; j++) {
			inst->watch_dirs[i].service_addrs[j] = 0;
		}
		inst->watch_dirs[i].service_count = 0;
	}
	inst->watch_count = 0;
}

static int
remove_service_from_watch(struct sinotify_service *inst, uint32_t service_addr) {
	int removed_count = 0;
	for (int i = 0; i < inst->watch_count; i++) {
		for (int j = 0; j < inst->watch_dirs[i].service_count; j++) {
			if (inst->watch_dirs[i].service_addrs[j] == service_addr) {
				for (int k = j; k < inst->watch_dirs[i].service_count - 1; k++) {
					inst->watch_dirs[i].service_addrs[k] = inst->watch_dirs[i].service_addrs[k + 1];
				}
				inst->watch_dirs[i].service_addrs[inst->watch_dirs[i].service_count - 1] = 0;
				inst->watch_dirs[i].service_count--;
				removed_count++;
				skynet_error(inst->ctx, "[sinotify] Removed service %u from watch %s (remaining services: %d)\n", 
					service_addr, inst->watch_dirs[i].path, inst->watch_dirs[i].service_count);
				j--;
			}
		}
	}
	return removed_count;
}

static void
cleanup_empty_watches(struct sinotify_service *inst) {
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].service_count == 0) {
			if (inst->watch_dirs[i].watch_descriptor >= 0) {
				inotify_rm_watch(inst->inotify_fd, inst->watch_dirs[i].watch_descriptor);
				skynet_error(inst->ctx, "[sinotify] Removed empty watch for %s (wd=%d)\n", 
					inst->watch_dirs[i].path, inst->watch_dirs[i].watch_descriptor);
			}
			
			if (inst->watch_dirs[i].path) {
				skynet_free(inst->watch_dirs[i].path);
			}
			
			for (int j = i; j < inst->watch_count - 1; j++) {
				inst->watch_dirs[j] = inst->watch_dirs[j + 1];
			}
			
			inst->watch_dirs[inst->watch_count - 1].path = NULL;
			inst->watch_dirs[inst->watch_count - 1].watch_descriptor = -1;
			for (int k = 0; k < MAX_SERVICE_ADDRS; k++) {
				inst->watch_dirs[inst->watch_count - 1].service_addrs[k] = 0;
			}
			inst->watch_dirs[inst->watch_count - 1].service_count = 0;
			
			inst->watch_count--;
			i--;
		}
	}
}

static struct watch_entry*
find_watch_entry(struct sinotify_service *inst, int wd) {
	for (int i = 0; i < inst->watch_count; i++) {
		if (inst->watch_dirs[i].watch_descriptor == wd) {
			return &inst->watch_dirs[i];
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
		
		struct watch_entry *watch_entry = find_watch_entry(inst, event->wd);
		if (!watch_entry) {
			skynet_error(inst->ctx, "[sinotify] Unknown watch descriptor: %d", event->wd);
			i += EVENT_SIZE + event->len;
			continue;
		}
		
		const char *watch_path = watch_entry->path;
		
		char full_path[PATH_MAX];
		if (event->len > 0) {
			int watch_path_len = strlen(watch_path);
			if (watch_path_len > 0 && watch_path[watch_path_len - 1] == '/') {
				snprintf(full_path, sizeof(full_path), "%s%s", watch_path, event->name);
			} else {
				snprintf(full_path, sizeof(full_path), "%s/%s", watch_path, event->name);
			}
		} else {
			strcpy(full_path, watch_path);
		}
		
		if (event->len > 0) {
			const char* event_name = get_event_name(event->mask);
			skynet_error(inst->ctx, "[sinotify] change %s: %s", event_name, event->name);
			
			if (watch_entry->service_count > 0) {
				char notify_msg[PATH_MAX * 2];
				snprintf(notify_msg, sizeof(notify_msg), "%s|%s", 
					event_name, full_path);
				
				for (int i = 0; i < watch_entry->service_count; i++) {
					uint32_t service_addr = watch_entry->service_addrs[i];
					if (service_addr != 0) {
						skynet_error(inst->ctx, "[sinotify] Notifying service %u: %s", service_addr, notify_msg);
						skynet_send(inst->ctx, 0, service_addr, PTYPE_CLIENT, 0, notify_msg, strlen(notify_msg));
					}
				}
			}
			
			if ((event->mask & IN_CREATE) && (event->mask & IN_ISDIR)) {
				skynet_error(inst->ctx, "[sinotify] New directory created, adding recursive watch: %s", full_path);
				add_watch_recursive(inst, full_path);
			}
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
	struct sinotify_service * inst = (struct sinotify_service *)ud;
	skynet_error(context, "[sinotify] callback type: %d, session: %d, source: %u, sz: %zu", type, session, source, sz);
	switch (type) {
	case PTYPE_SOCKET: {
		struct skynet_socket_message * socket_msg = (struct skynet_socket_message *)msg;
		skynet_error(context, "[sinotify] socket type: %d, id: %d", socket_msg->type, socket_msg->id);
		
		if (socket_msg->id == inst->socket_id) {
			switch (socket_msg->type) {
			case SKYNET_SOCKET_TYPE_CONNECT:
				skynet_error(inst->ctx, "[sinotify] socket connected");
				break;
			case SKYNET_SOCKET_TYPE_DATA:
				skynet_error(inst->ctx, "[sinotify] Received SKYNET_SOCKET_TYPE_DATA message, size=%d", socket_msg->ud);
				
				if (socket_msg->buffer && socket_msg->ud > 0) {
					handle_sinotify_events(inst, socket_msg->buffer, socket_msg->ud);
					skynet_free(socket_msg->buffer);
				} else {
					skynet_error(inst->ctx, "[sinotify] No data in socket message");
				}
				break;
			case SKYNET_SOCKET_TYPE_ERROR: 
				skynet_error(inst->ctx, "[sinotify] socket error occurred");
				break;
			case SKYNET_SOCKET_TYPE_CLOSE: 
				skynet_error(inst->ctx, "[sinotify] socket closed");
				break;
			default:
				skynet_error(inst->ctx, "[sinotify] unknown socket message type: %d", socket_msg->type);
				break;
			}
		}
		break;
	}
	case PTYPE_CLIENT:
		if (sz > 0) {
			char *cmd = skynet_malloc(sz + 1);
			memcpy(cmd, msg, sz);
			cmd[sz] = '\0';
			skynet_error(context, "[sinotify] Received command: %s", cmd);
			if (strncmp(cmd, "stop", 4) == 0) {
				skynet_error(context, "[sinotify] Received stop command from service %u", source);
				int removed = remove_service_from_watch(inst, source);
				if (removed > 0) {
					skynet_error(context, "[sinotify] Removed service %u from %d watches", source, removed);
					cleanup_empty_watches(inst);
					skynet_error(context, "[sinotify] Cleaned up empty watches, remaining watches: %d", inst->watch_count);
				} else {
					skynet_error(context, "[sinotify] Service %u was not registered for any watches", source);
				}
			} else if (strncmp(cmd, "add_watch", 9) == 0) {
				char *params = cmd + 9; 
				skynet_error(context, "[sinotify] add_watch %s", params);
				if (params) {
					int wd = add_single_watch_with_callback(inst, params, source);
					if (wd >= 0) {
						skynet_error(context, "[sinotify] Added watch for %s with callback %d", params, source);
					} else {
						skynet_error(context, "[sinotify] Failed to add watch for %s", params);
					}
				} else {
					skynet_error(context, "[sinotify] Invalid add_watch command format. Usage: add_watch watch_path %s", params);
				}
			} else {
				skynet_error(context, "[sinotify] Unknown command: %s (available: stop, add_watch)", cmd);
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
	inst->inotify_fd = inotify_init();
	if (inst->inotify_fd < 0) {
		skynet_error(ctx, "[sinotify] Failed to initialize inotify: %s", strerror(errno));
		return 1;
	}
	
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
	
	char *abs_path = realpath(inst->watch_path, NULL);
	if (abs_path) {
		skynet_error(ctx, "[sinotify] Absolute path to watch: %s", abs_path);
		free(abs_path);
	} else {
		skynet_error(ctx, "[sinotify] Warning: cannot resolve absolute path for %s: %s", inst->watch_path, strerror(errno));
	}
	
	struct stat st;
	if (stat(inst->watch_path, &st) != 0) {
		skynet_error(ctx, "[sinotify] Error: cannot access directory %s: %s", inst->watch_path, strerror(errno));
		return 1;
	}
	if (!S_ISDIR(st.st_mode)) {
		skynet_error(ctx, "[sinotify] Error: %s is not a directory", inst->watch_path);
		return 1;
	}
	
	inst->watch_count = 0;
	for (int i = 0; i < MAX_WATCH_DIRS; i++) {
		inst->watch_dirs[i].path = NULL;
		inst->watch_dirs[i].watch_descriptor = -1;
		for (int j = 0; j < MAX_SERVICE_ADDRS; j++) {
			inst->watch_dirs[i].service_addrs[j] = 0;
		}
		inst->watch_dirs[i].service_count = 0;
	}
	
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
	
	skynet_error(ctx, "[sinotify] Adding recursive watch for %s\n", inst->watch_path);
	if (add_watch_recursive(inst, inst->watch_path) < 0) {
		skynet_error(ctx, "[sinotify] Failed to add recursive watch for %s\n", inst->watch_path);
		return 1;
	}
	skynet_error(ctx, "[sinotify] Started watching directory recursively: %s (total watches=%d)\n", inst->watch_path, inst->watch_count);
	
	skynet_callback(ctx, inst, sinotify_cb);
	
	inst->socket_id = skynet_socket_bind(ctx, inst->inotify_fd);
	if (inst->socket_id < 0) {
		skynet_error(ctx, "[sinotify] Failed to bind inotify fd to skynet socket");
		return 1;
	}
	
	skynet_socket_start(ctx, inst->socket_id);
	
	skynet_error(ctx, "[sinotify] Service initialized successfully, socket_id=%d", inst->socket_id);
	return 0;
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
		for (int j = 0; j < MAX_SERVICE_ADDRS; j++) {
			inst->watch_dirs[i].service_addrs[j] = 0;
		}
		inst->watch_dirs[i].service_count = 0;
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
