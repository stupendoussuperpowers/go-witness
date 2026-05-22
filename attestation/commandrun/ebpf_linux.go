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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/in-toto/go-witness/attestation"
	commandrunbpf "github.com/in-toto/go-witness/attestation/commandrun/bpf"
	"github.com/in-toto/go-witness/cryptoutil"
	"golang.org/x/sys/unix"
)

const (
	commandRunTraceCgroupPath = "/sys/fs/cgroup/witness-commandrun"
)

type fileOpenEvent struct {
	EventType uint32
	PID       uint32
	TID       uint32
	Dfd       int32
	Path      [256]byte
}

const (
	eventTypeOpen = 1
	eventTypeFork = 2
	eventTypeExec = 3
	eventTypeExit = 4
)

type ebpfTraceContext struct {
	hash      []cryptoutil.DigestValue
	processes map[int]*ProcessInfo
	seenExec  map[int]bool
	seenLife  map[int]bool
	mu        sync.Mutex
}

func (rc *CommandRun) traceWithEBPF(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	cgroupFile, cgroupID, err := prepareCommandRunTraceCgroup()
	if err != nil {
		return nil, err
	}
	defer cgroupFile.Close()

	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	c.SysProcAttr.UseCgroupFD = true
	c.SysProcAttr.CgroupFD = int(cgroupFile.Fd())

	spec, err := commandrunbpf.LoadFiletrace()
	if err != nil {
		return nil, fmt.Errorf("load command-run file trace spec: %w", err)
	}
	if err := spec.Variables["target_cgroup_id"].Set(cgroupID); err != nil {
		return nil, fmt.Errorf("set target cgroup id: %w", err)
	}

	var objs commandrunbpf.FiletraceObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load command-run file trace objects: %w", err)
	}
	defer objs.Close()

	links := make([]link.Link, 0, 6)
	defer closeLinks(links)

	traceOpen, err := link.Tracepoint("syscalls", "sys_enter_open", objs.TraceOpen, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sys_enter_open: %w", err)
	}
	links = append(links, traceOpen)

	traceOpenAt, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sys_enter_openat: %w", err)
	}
	links = append(links, traceOpenAt)

	traceOpenAt2, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.TraceOpenat2, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sys_enter_openat2: %w", err)
	}
	links = append(links, traceOpenAt2)
	traceFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceSchedProcessFork, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sched_process_fork: %w", err)
	}
	links = append(links, traceFork)
	traceExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sched_process_exec: %w", err)
	}
	links = append(links, traceExec)
	traceExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceSchedProcessExit, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}
	links = append(links, traceExit)

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("create command-run file trace reader: %w", err)
	}

	pctx := &ebpfTraceContext{
		hash:      actx.Hashes(),
		processes: make(map[int]*ProcessInfo),
		seenExec:  make(map[int]bool),
		seenLife:  make(map[int]bool),
	}

	var readErr error
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		readErr = pctx.readEvents(reader)
	}()

	if err := c.Start(); err != nil {
		reader.Close()
		readerWg.Wait()
		return nil, err
	}

	pctx.mu.Lock()
	pctx.getProcInfo(c.Process.Pid)
	pctx.mu.Unlock()

	waitErr := c.Wait()
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		rc.ExitCode = exitErr.ExitCode()
	}
	if waitErr == nil && c.ProcessState != nil {
		rc.ExitCode = c.ProcessState.ExitCode()
	}

	_ = reader.Close()
	readerWg.Wait()
	if readErr != nil {
		return nil, readErr
	}

	pctx.finalizeOpenedFiles()

	if waitErr != nil {
		return pctx.procInfoArray(), waitErr
	}

	return pctx.procInfoArray(), nil
}

func (p *ebpfTraceContext) readEvents(reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}

		var event fileOpenEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return err
		}

		pid := int(event.PID)
		var shouldEnrich bool
		p.mu.Lock()
		procInfo := p.getProcInfo(pid)
		switch event.EventType {
		case eventTypeOpen:
			path := cleanString(string(event.Path[:]))
			if path != "" {
				resolvedPath := path
				if !filepath.IsAbs(path) && event.Dfd == unix.AT_FDCWD {
					if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", event.PID)); err == nil {
						resolvedPath = filepath.Join(cwd, path)
					}
				}
				if _, exists := procInfo.OpenedFiles[resolvedPath]; !exists {
					procInfo.OpenedFiles[resolvedPath] = nil
				}
			}
		case eventTypeFork:
			p.seenLife[pid] = true
			if procInfo.ParentPID == 0 && event.Dfd > 0 {
				procInfo.ParentPID = int(event.Dfd)
			}
			shouldEnrich = true
		case eventTypeExec:
			p.seenExec[pid] = true
			p.seenLife[pid] = true
			shouldEnrich = true
		case eventTypeExit:
			p.seenLife[pid] = true
			shouldEnrich = true
		}
		p.mu.Unlock()
		if shouldEnrich {
			p.populateMetadataForProc(pid)
		}
	}
}

func (p *ebpfTraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := p.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}
		p.processes[pid] = procInfo
	}

	return procInfo
}

func (p *ebpfTraceContext) procInfoArray() []ProcessInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	processes := make([]ProcessInfo, 0, len(p.processes))
	for pid, procInfo := range p.processes {
		// Keep parity with ptrace-style reporting:
		// include entries that were observed by lifecycle hooks, exec hooks,
		// or opened files.
		if !p.seenLife[pid] && !p.seenExec[pid] && len(procInfo.OpenedFiles) == 0 {
			continue
		}
		// Drop obvious helper/kernel-worker style tasks that ptrace flow
		// typically does not materialize as command-run processes.
		if strings.HasPrefix(procInfo.Comm, "iou-sqp-") {
			continue
		}
		// Filter obvious garbage rows produced by transient/bad metadata states.
		// Keep real auxiliary rows (often parent=0 with sparse fields) as long as
		// they were observed via lifecycle/file activity.
		if procInfo.Program != "" && !strings.HasPrefix(procInfo.Program, "/") {
			if procInfo.Comm == "" && procInfo.Cmdline == "" && len(procInfo.OpenedFiles) == 0 {
				continue
			}
		}
		processes = append(processes, *procInfo)
	}

	return processes
}

func (p *ebpfTraceContext) finalizeOpenedFiles() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, procInfo := range p.processes {
		for file, digestSet := range procInfo.OpenedFiles {
			if digestSet != nil {
				continue
			}

			digest, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
			if err == nil {
				procInfo.OpenedFiles[file] = digest
			}
		}
	}
}

func (p *ebpfTraceContext) populateMetadataForProc(pid int) {
	statusBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

	var ppid int
	if len(statusBytes) > 0 {
		if parsedPPID, err := getPPIDFromStatus(statusBytes); err == nil {
			ppid = parsedPPID
		}
	}
	comm := ""
	if len(statusBytes) > 0 {
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "Name:") {
				comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				break
			}
		}
	}
	cmdline := ""
	if len(cmdlineBytes) > 0 {
		parts := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			cmdline = strings.Join(parts, " ")
		}
	}
	var exeDigest cryptoutil.DigestSet
	if exePath != "" {
		if digest, err := cryptoutil.CalculateDigestSetFromFile(exePath, p.hash); err == nil {
			exeDigest = digest
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	procInfo, ok := p.processes[pid]
	if !ok {
		return
	}
	if procInfo.ParentPID == 0 && ppid > 0 {
		procInfo.ParentPID = ppid
	}
	if procInfo.Comm == "" && comm != "" {
		procInfo.Comm = comm
	}
	if procInfo.Cmdline == "" && cmdline != "" {
		procInfo.Cmdline = cmdline
	}
	if procInfo.Program == "" && exePath != "" {
		procInfo.Program = exePath
	}
	if procInfo.ExeDigest == nil && exeDigest != nil {
		procInfo.ExeDigest = exeDigest
	}
}

func prepareCommandRunTraceCgroup() (*os.File, uint64, error) {
	if err := os.MkdirAll(commandRunTraceCgroupPath, 0o755); err != nil {
		return nil, 0, fmt.Errorf("create command-run trace cgroup: %w", err)
	}

	file, err := os.Open(commandRunTraceCgroupPath)
	if err != nil {
		return nil, 0, fmt.Errorf("open command-run trace cgroup: %w", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(commandRunTraceCgroupPath, &stat); err != nil {
		file.Close()
		return nil, 0, fmt.Errorf("stat command-run trace cgroup: %w", err)
	}

	return file, stat.Ino, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
}
