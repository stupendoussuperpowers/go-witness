//go:build ignore

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

#include "vmlinux.h"
#include <bpf_helpers.h>

#include "filetrace_common.h"

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pending_open {
	__u64 filename;
	__s32 dfd;
	__s64 error;
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192 * 12);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

static __always_inline int save_open_event(const char *filename, __s32 dfd) {
	if (!commandrun_in_target_cgroup()) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open pending = {
	    .filename = (__u64)filename,
	    .dfd = dfd,
	    .error = 0,
	};

	long copied = bpf_probe_read_user_str(pending.path,
					      sizeof(pending.path), filename);
	if (copied < 0) {
		pending.error = copied;
		pending.path[0] = '\0';
	} else {
		pending.error = copied;
	}

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

	if (!commandrun_in_target_cgroup()) {
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
	event->error = pending->error;

	if (pending->error < 0) {
		const char *filename = (const char *)pending->filename;
		long copied = bpf_probe_read_user_str(
		    event->path, sizeof(event->path), filename);
		if (copied < 0) {
			event->event_type = EVENT_TYPE_ERROR;
			event->error = copied;
			event->path[0] = '\0';
			bpf_ringbuf_submit(event, 0);
			bpf_map_delete_elem(&pending_opens, &pid_tgid);
			return 0;
		}
		event->error = copied;
		bpf_ringbuf_submit(event, 0);
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	__builtin_memcpy(event->path, pending->path, sizeof(event->path));
	event->path[sizeof(event->path) - 1] = '\0';

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
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
