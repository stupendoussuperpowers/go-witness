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

#ifndef WITNESS_COMMANDRUN_FILETRACE_COMMON_H
#define WITNESS_COMMANDRUN_FILETRACE_COMMON_H

volatile const __u64 target_cgroup_id = 0;

struct file_open_event {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__s32 dfd;
	__s64 error;
	char path[256];
};

enum event_type {
	EVENT_TYPE_OPEN = 1,
	EVENT_TYPE_EXEC = 2,
	EVENT_TYPE_EXIT = 3,
	EVENT_TYPE_ERROR = 4,
};

enum error_type {
	ERROR_TYPE_PENDING_OPEN_UPDATE = 1,
	ERROR_TYPE_PENDING_OPEN_MISSING = 2,
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

static __always_inline int commandrun_in_target_cgroup() {
	if (target_cgroup_id == 0) {
		return 0;
	}
	return bpf_get_current_cgroup_id() == target_cgroup_id;
}

static __always_inline void submit_error_event(__s64 error) {
	if (!commandrun_in_target_cgroup()) {
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
	event->error = error;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct sched_process_exec_args *ctx) {
	if (!commandrun_in_target_cgroup()) {
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
	if (!commandrun_in_target_cgroup()) {
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
	event->error = 0;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
	return 0;
}

#endif
