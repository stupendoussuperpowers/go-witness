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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/in-toto/go-witness/attestation"
	commandrunbpf "github.com/in-toto/go-witness/attestation/commandrun/bpf"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

const (
	commandRunTraceCgroupPath = "/sys/fs/cgroup/witness-commandrun"
	commandRunDigestJobBuffer = 1 << 16
	commandRunDigestWorkers   = 4
)

type digestJob struct {
	pid  int
	path string
}

type fileOpenEvent struct {
	EventType uint32
	PID       uint32
	TID       uint32
	Dfd       int32
	Fd        int32
	Error     int64
	Cwd       [256]byte
	Path      [256]byte
}

const (
	eventTypeOpen  = 1
	eventTypeFork  = 2
	eventTypeExec  = 3
	eventTypeExit  = 4
	eventTypeError = 5
)

const (
	errorTypePendingOpenUpdate  = 1
	errorTypePendingOpenMissing = 2
)

type ebpfTraceContext struct {
	hash       []cryptoutil.DigestValue
	processes  map[int]*ProcessInfo
	digestJobs chan digestJob
	digestWg   sync.WaitGroup
	mu         sync.Mutex
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

	links := make([]link.Link, 0, 10)
	defer closeLinks(links)

	tracepoints := []struct {
		group   string
		name    string
		program *ebpf.Program
	}{
		{"syscalls", "sys_enter_open", objs.TraceOpen},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2},
		{"syscalls", "sys_exit_open", objs.TraceOpenExit},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit},
		{"sched", "sched_process_exec", objs.TraceSchedProcessExec},
		{"sched", "sched_process_exit", objs.TraceSchedProcessExit},
	}
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.program, nil)
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", tp.name, err)
		}
		links = append(links, l)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("create command-run file trace reader: %w", err)
	}

	pctx := &ebpfTraceContext{
		hash:      actx.Hashes(),
		processes: make(map[int]*ProcessInfo),
	}
	pctx.startDigestWorkers(commandRunDigestWorkers)

	var readErr error
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		if err := pctx.readEvents(reader); err != nil {
			readErr = err
			log.Errorf("command-run eBPF trace error: %v", err)
			if c.Process != nil {
				_ = c.Process.Kill()
			}
		}
	}()

	if err := c.Start(); err != nil {
		reader.Close()
		readerWg.Wait()
		pctx.finishDigestWorkers()
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
	pctx.finishDigestWorkers()
	if readErr != nil {
		return pctx.procInfoArray(), readErr
	}

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

		if event.EventType == eventTypeError {
			return formatEBPFTraceError(event)
		}

		var shouldEnrich bool
		pid := int(event.PID)
		var digestPath string

		var procInfo *ProcessInfo

		p.mu.Lock()

		switch event.EventType {
		case eventTypeOpen:
			pid = int(event.TID)
			procInfo = p.getProcInfo(pid)

			path := cleanString(string(event.Path[:]))
			if path != "" {
				openPath := path
				if !filepath.IsAbs(path) {
					if base := cleanString(string(event.Cwd[:])); base != "" {
						openPath = filepath.Join(base, path)
					}
				}
				if _, exists := procInfo.OpenedFiles[openPath]; !exists {
					procInfo.OpenedFiles[openPath] = nil
					digestPath = openPath
				}
			}

		case eventTypeFork:
			procInfo = p.getProcInfo(pid)
			if procInfo.ParentPID == 0 && event.Dfd > 0 {
				procInfo.ParentPID = int(event.Dfd)
			}
			shouldEnrich = true
		case eventTypeExec:
			procInfo = p.getProcInfo(pid)
			shouldEnrich = true
		case eventTypeExit:
			procInfo = p.processes[pid]
			if procInfo != nil {
				shouldEnrich = true
			}
		}

		p.mu.Unlock()

		if digestPath != "" {
			p.enqueueDigestJob(digestJob{pid: pid, path: digestPath})
		}

		if shouldEnrich {
			p.populateMetadataForProc(pid, event.EventType == eventTypeExec)
		}
	}
}

func formatEBPFTraceError(event fileOpenEvent) error {
	switch event.Error {
	case errorTypePendingOpenUpdate:
		return fmt.Errorf("command-run eBPF trace failed to store pending open for pid %d tid %d", event.PID, event.TID)
	case errorTypePendingOpenMissing:
		return fmt.Errorf("command-run eBPF trace missing pending open for pid %d tid %d", event.PID, event.TID)
	default:
		return fmt.Errorf("command-run eBPF trace failed to read opened filename for pid %d tid %d: %d", event.PID, event.TID, event.Error)
	}
}

func (p *ebpfTraceContext) startDigestWorkers(count int) {
	p.digestJobs = make(chan digestJob, commandRunDigestJobBuffer)
	for range count {
		p.digestWg.Add(1)
		go p.digestWorker()
	}
}

func (p *ebpfTraceContext) finishDigestWorkers() {
	close(p.digestJobs)
	p.digestWg.Wait()
}

func (p *ebpfTraceContext) enqueueDigestJob(job digestJob) {
	select {
	case p.digestJobs <- job:
	default:
	}
}

func (p *ebpfTraceContext) digestWorker() {
	defer p.digestWg.Done()
	for job := range p.digestJobs {
		digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, p.hash)
		if err != nil {
			continue
		}

		p.mu.Lock()
		if procInfo := p.processes[job.pid]; procInfo != nil {
			if procInfo.OpenedFiles[job.path] == nil {
				procInfo.OpenedFiles[job.path] = digest
			}
		}
		p.mu.Unlock()
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
		// Minimal normalization: if program is missing but comm has a simple
		// executable-like token, promote comm to program for ptrace-like output.
		if procInfo.Program == "" && procInfo.Comm != "" && !strings.Contains(procInfo.Comm, " ") {
			procInfo.Program = procInfo.Comm
		}
		processes = append(processes, *procInfo)
	}

	return processes
}

func (p *ebpfTraceContext) populateMetadataForProc(pid int, overwrite bool) {
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
	if (overwrite || procInfo.Comm == "") && comm != "" {
		procInfo.Comm = comm
	}
	if (overwrite || procInfo.Cmdline == "") && cmdline != "" {
		procInfo.Cmdline = cmdline
	}
	if (overwrite || procInfo.Program == "") && exePath != "" {
		procInfo.Program = exePath
	}
	if (overwrite || procInfo.ExeDigest == nil) && exeDigest != nil {
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
