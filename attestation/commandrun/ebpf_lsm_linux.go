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

//go:build linux

package commandrun

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	commandrunbpf "github.com/in-toto/go-witness/attestation/commandrun/bpf"
)

func loadLSMEBPFTracer(cgroupID uint64) (*loadedEBPFTracer, error) {
	if !bpfLSMAvailable() {
		return nil, fmt.Errorf("BPF LSM is not enabled")
	}

	spec, err := commandrunbpf.LoadFiletraceLsm()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["target_cgroup_id"].Set(cgroupID); err != nil {
		return nil, fmt.Errorf("set target cgroup id: %w", err)
	}

	var objs commandrunbpf.FiletraceLsmObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	links := make([]link.Link, 0, 3)
	for _, tp := range []struct {
		group   string
		name    string
		program *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.TraceSchedProcessExec},
		{"sched", "sched_process_exit", objs.TraceSchedProcessExit},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.program, nil)
		if err != nil {
			closeLinks(links)
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		links = append(links, l)
	}

	lsm, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmFileOpen})
	if err != nil {
		closeLinks(links)
		objs.Close()
		return nil, fmt.Errorf("attach LSM file_open: %w", err)
	}
	links = append(links, lsm)

	return &loadedEBPFTracer{
		events: objs.Events,
		close: func() error {
			closeLinks(links)
			return objs.Close()
		},
	}, nil
}

func bpfLSMAvailable() bool {
	lsmBytes, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}

	for _, lsm := range strings.Split(strings.TrimSpace(string(lsmBytes)), ",") {
		if lsm == "bpf" {
			return true
		}
	}

	return false
}
