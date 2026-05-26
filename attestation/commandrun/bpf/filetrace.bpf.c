// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const __u64 target_cgroup_id = 0;

struct pending_open {
	__u64 filename;
	__s32 dfd;
};

struct file_open_event {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__s32 dfd;
	__s32 fd;
	__s64 error;
	char path[256];
};

enum event_type {
	EVENT_TYPE_OPEN = 1,
	EVENT_TYPE_FORK = 2,
	EVENT_TYPE_EXEC = 3,
	EVENT_TYPE_EXIT = 4,
	EVENT_TYPE_ERROR = 5,
};

enum error_type {
	ERROR_TYPE_PENDING_OPEN_UPDATE = 1,
	ERROR_TYPE_PENDING_OPEN_MISSING = 2,
	ERROR_TYPE_READ_FILENAME = 3,
};

struct sched_process_fork_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	char parent_comm[16];
	__s32 parent_pid;
	char child_comm[16];
	__s32 child_pid;
};

struct sched_process_exec_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	char filename[256];
	__s32 pid;
	__s32 old_pid;
};

struct sched_process_exit_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	char comm[16];
	__s32 pid;
	__s32 prio;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 29);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192 * 12);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

static __always_inline void submit_error_event(__s64 error) {
	if (target_cgroup_id == 0) {
		return;
	}
	if (bpf_get_current_cgroup_id() != target_cgroup_id) {
		return;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->event_type = EVENT_TYPE_ERROR;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = 0;
	event->fd = 0;
	event->error = error;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
}

static __always_inline int save_open_event(const char *filename, __s32 dfd) {
	if (target_cgroup_id == 0) {
		return 0;
	}

	__u64 current_cgroup_id = bpf_get_current_cgroup_id();
	if (current_cgroup_id != target_cgroup_id) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open pending = {
	    .filename = (__u64)filename,
	    .dfd = dfd,
	};
	long update_ret =
	    bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	if (update_ret < 0) {
		submit_error_event(ERROR_TYPE_PENDING_OPEN_UPDATE);
	}
	return 0;
}

static __always_inline int submit_pending_open_event(__s64 ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending =
	    bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending) {
		submit_error_event(ERROR_TYPE_PENDING_OPEN_MISSING);
		return 0;
	}

	if (ret < 0) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	__u64 current_cgroup_id = bpf_get_current_cgroup_id();
	if (target_cgroup_id == 0 || current_cgroup_id != target_cgroup_id) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	event->event_type = EVENT_TYPE_OPEN;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = pending->dfd;
	event->fd = ret;
	event->error = 0;

	const char *filename = (const char *)pending->filename;
	long copied =
	    bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
	if (copied < 0) {
		event->event_type = EVENT_TYPE_ERROR;
		event->error = copied;
		event->path[0] = '\0';
		bpf_ringbuf_submit(event, 0);
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct sched_process_fork_args *ctx) {
	if (target_cgroup_id == 0) {
		return 0;
	}
	if (bpf_get_current_cgroup_id() != target_cgroup_id) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_FORK;
	event->pid = ctx->child_pid;
	event->tid = ctx->child_pid;
	event->dfd = ctx->parent_pid;
	event->fd = 0;
	event->error = 0;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct sched_process_exec_args *ctx) {
	if (target_cgroup_id == 0) {
		return 0;
	}
	if (bpf_get_current_cgroup_id() != target_cgroup_id) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->event_type = EVENT_TYPE_EXEC;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = 0;
	event->fd = 0;
	event->error = 0;
	long copied = bpf_probe_read_kernel_str(
	    event->path, sizeof(event->path), ctx->filename);
	if (copied < 0) {
		event->path[0] = '\0';
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct sched_process_exit_args *ctx) {
	if (target_cgroup_id == 0) {
		return 0;
	}
	if (bpf_get_current_cgroup_id() != target_cgroup_id) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_EXIT;
	event->pid = ctx->pid;
	event->tid = ctx->pid;
	event->dfd = 0;
	event->fd = 0;
	event->error = 0;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[0], AT_FDCWD);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}
