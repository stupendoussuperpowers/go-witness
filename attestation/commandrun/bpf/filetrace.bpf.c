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

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const __u64 target_cgroup_id = 0;

struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long id;
	unsigned long args[6];
};

struct file_open_event {
	__u32 pid;
	__u32 tid;
	__s32 dfd;
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int submit_open_event(const char *filename, __s32 dfd) {
	if (target_cgroup_id == 0) {
		return 0;
	}

	if (bpf_get_current_cgroup_id() != target_cgroup_id) {
		return 0;
	}

	struct file_open_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = dfd;

	long copied = bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
	if (copied < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
	return submit_open_event((const char *)ctx->args[0], AT_FDCWD);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	return submit_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx) {
	return submit_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}
