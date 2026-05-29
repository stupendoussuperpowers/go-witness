// go:build ignore

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
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "filetrace_common.h"

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef FMODE_EXEC
#define FMODE_EXEC 0x20
#endif

#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
	if (!commandrun_in_target_cgroup()) {
		return 0;
	}

	fmode_t mode = file->f_mode;
	if (mode & FMODE_EXEC) {
		return 0;
	}

	char path[256];
	__builtin_memset(path, 0, sizeof(path));

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->event_type = EVENT_TYPE_OPEN;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = AT_FDCWD;
	event->error = 0;

	long ret = bpf_d_path(&file->f_path, path, sizeof(path));
	if (ret < 0) {
		event->event_type = EVENT_TYPE_ERROR;
		event->error = ret;
		event->path[0] = '\0';
		bpf_ringbuf_submit(event, 0);
		return -EPERM;
	}

	path[sizeof(path) - 1] = '\0';
	__builtin_memcpy(event->path, path, sizeof(event->path));
	event->path[sizeof(event->path) - 1] = '\0';
	event->error = ret;

	bpf_ringbuf_submit(event, 0);
	return 0;
}
