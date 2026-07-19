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

package workloadrun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	commandrunbpf "github.com/in-toto/go-witness/attestation/commandrun/bpf"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

const (
	eventTypeOpen        = 1
	eventTypeExec        = 2
	eventTypeExit        = 3
	eventTypeError       = 4
	eventTypeCgroupMkdir = 5
	eventTypeMount       = 6
)

const (
	errorTypePendingOpenUpdate  = 1
	errorTypePendingOpenMissing = 2
)

const (
	cgroupFileDigestJobBuffer = 1 << 16
	cgroupFileDigestWorkers   = 4
)

type cgroupFileEvent struct {
	EventType  uint32
	PID        uint32
	TID        uint32
	HostPID    uint32
	HostTID    uint32
	Dfd        int32
	Error      int64
	Path       [256]byte
	CgroupID   uint64
	MountDev   [256]byte
	MountDir   [256]byte
	MountType  [64]byte
	MountData  [256]byte
	MountFlags uint64
}

type CgroupFileDetector struct {
	loaded *loadedCgroupFileTracer
	reader *ringbuf.Reader
	cancel context.CancelFunc
	wg     sync.WaitGroup

	hash       []cryptoutil.DigestValue
	digestJobs chan cgroupFileDigestJob
	mu         sync.Mutex
	cgroups    map[uint64]Cgroup
	readErr    error
}

type cgroupFileDigestJob struct {
	cgroup Cgroup
	path   string
}

type loadedCgroupFileTracer struct {
	events        *ebpf.Map
	targetCgroups *ebpf.Map
	close         func() error
}

func NewCgroupFileDetector() *CgroupFileDetector {
	return &CgroupFileDetector{
		cgroups: make(map[uint64]Cgroup),
	}
}

func (c *CgroupFileDetector) Name() string {
	return "cgroup-file"
}

// Start attaches cgroup, open, exec, and exit tracepoints and begins reading events.
func (c *CgroupFileDetector) Start(ctx context.Context, attestor *Attestor, hash []cryptoutil.DigestValue) error {
	log.Infof("(%s) starting cgroup-file eBPF collector", Name)
	loaded, err := loadCgroupFileTracer()
	if err != nil {
		return err
	}

	reader, err := ringbuf.NewReader(loaded.events)
	if err != nil {
		loaded.close()
		return fmt.Errorf("create workload-run file trace reader: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	c.loaded = loaded
	c.reader = reader
	c.cancel = cancel
	c.hash = hash
	c.digestJobs = make(chan cgroupFileDigestJob, cgroupFileDigestJobBuffer)

	for range cgroupFileDigestWorkers {
		c.wg.Add(1)
		go c.digestWorker(attestor)
	}

	c.wg.Add(1)
	go c.readEvents(ctx, attestor)
	log.Infof("(%s) started cgroup-file eBPF collector", Name)
	return nil
}

// Stop tears down tracepoints and waits for the reader and digest workers.
func (c *CgroupFileDetector) Stop() error {
	log.Infof("(%s) cgroup-file stop: begin", Name)
	if c.cancel != nil {
		c.cancel()
	}
	if c.reader != nil {
		_ = c.reader.Close()
	}
	c.wg.Wait()
	log.Infof("(%s) cgroup-file stop: reader done cgroups=%d", Name, len(c.cgroups))
	if c.loaded != nil {
		if err := c.loaded.close(); err != nil {
			return err
		}
	}
	log.Infof("(%s) cgroup-file stop: done", Name)
	return c.readErr
}

// Main loop to read eBPF events.
// Events of importance are: new cgroup creations, new process creations, file opens.
func (c *CgroupFileDetector) readEvents(ctx context.Context, attestor *Attestor) {
	defer c.wg.Done()
	defer close(c.digestJobs)
	log.Infof("(%s) cgroup-file reader: started", Name)
	defer log.Infof("(%s) cgroup-file reader: stopped", Name)

	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				log.Infof("(%s) cgroup-file reader: exiting err=%v ctx_err=%v", Name, err, ctx.Err())
				return
			}
			c.readErr = err
			log.Infof("(%s) cgroup-file reader: error: %v", Name, err)
			return
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			c.readErr = err
			log.Infof("(%s) cgroup-file reader: %v", Name, err)
			return
		}
		if event.EventType == eventTypeError {
			err := formatCgroupFileTraceError(event)
			if event.Error == errorTypePendingOpenMissing {
				log.Warnf("(%s) cgroup-file reader: %v", Name, err)
				continue
			}
			c.readErr = err
			log.Infof("(%s) cgroup-file reader: %v", Name, c.readErr)
			return
		}

		switch event.EventType {
		case eventTypeCgroupMkdir:
			c.handleCgroupMkdir(attestor, event)
		case eventTypeOpen:
			c.handleOpen(attestor, event)
		case eventTypeMount:
			c.handleMount(attestor, event)
		case eventTypeExec, eventTypeExit:
			c.handleProcess(attestor, event)
		}
	}
}

// handleCgroupMkdir accepts provider-matched cgroups and adds them to the BPF allowlist.
func (c *CgroupFileDetector) handleCgroupMkdir(attestor *Attestor, event cgroupFileEvent) {
	path := cleanCString(event.Path[:])
	if path == "" || event.CgroupID == 0 || !attestor.AcceptCgroup(path) {
		log.Infof("(%s) ignored cgroup mkdir: id=%d path=%s", Name, event.CgroupID, path)
		return
	}

	cgroup := Cgroup{ID: event.CgroupID, Path: path}
	if err := c.loaded.addCgroup(cgroup.ID); err != nil {
		log.Infof("(%s) add cgroup to BPF allowlist failed: id=%d path=%s err=%v", Name, cgroup.ID, cgroup.Path, err)
		return
	}

	c.mu.Lock()
	c.cgroups[cgroup.ID] = cgroup
	c.mu.Unlock()

	log.Infof("(%s) tracking cgroup: id=%d path=%s", Name, cgroup.ID, cgroup.Path)
	attestor.AddCgroup(cgroup)
}

// handleOpen resolves accepted open events to paths and schedules digesting.
func (c *CgroupFileDetector) handleOpen(attestor *Attestor, event cgroupFileEvent) {
	cgroup, ok := c.cgroup(event.CgroupID)
	if !ok {
		return
	}

	path := cleanCString(event.Path[:])
	if path == "" {
		return
	}
	openPath := resolveOpenPath(int(event.HostTID), int(event.Dfd), path)
	if !attestor.AcceptFile(openPath) {
		return
	}

	attestor.AddProcess(cgroup, processInfo(int(event.PID), int(event.HostPID)))
	attestor.AddOpenedFile(cgroup, openPath, nil)
	c.enqueueDigestJob(cgroupFileDigestJob{cgroup: cgroup, path: openPath})
}

// handleMount records accepted mount events under the cgroup that emitted them.
func (c *CgroupFileDetector) handleMount(attestor *Attestor, event cgroupFileEvent) {
	cgroup, ok := c.cgroup(event.CgroupID)
	if !ok {
		return
	}

	mount := Mount{
		Device:     cleanCString(event.MountDev[:]),
		Directory:  cleanCString(event.MountDir[:]),
		Type:       cleanCString(event.MountType[:]),
		Data:       cleanCString(event.MountData[:]),
		Flags:      event.MountFlags,
		ProcessID:  int(event.PID),
		HostPID:    int(event.HostPID),
		HostTID:    int(event.HostTID),
		CgroupID:   event.CgroupID,
		CgroupPath: cgroup.Path,
	}
	if mount.Directory == "" || !attestor.AcceptMount(mount) {
		return
	}

	attestor.AddProcess(cgroup, processInfo(int(event.PID), int(event.HostPID)))
	attestor.AddMount(cgroup, mount)
}

func (c *CgroupFileDetector) enqueueDigestJob(job cgroupFileDigestJob) {
	select {
	case c.digestJobs <- job:
	default:
	}
}

// digestWorker hashes opened files after the event loop has recorded them.
func (c *CgroupFileDetector) digestWorker(attestor *Attestor) {
	defer c.wg.Done()
	for job := range c.digestJobs {
		if skipDigestPath(job.path) {
			continue
		}
		digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, c.hash)
		if err != nil {
			continue
		}
		attestor.AddOpenedFile(job.cgroup, job.path, digest)
	}
}

func skipDigestPath(path string) bool {
	for _, marker := range []string{"/root/", "/cwd/"} {
		_, rest, ok := strings.Cut(path, marker)
		if !ok {
			continue
		}

		if rest == "proc" || rest == "sys" || rest == "dev" ||
			strings.HasPrefix(rest, "proc/") || strings.HasPrefix(rest, "sys/") || strings.HasPrefix(rest, "dev/") {
			return true
		}
	}
	return false
}

func (c *CgroupFileDetector) handleProcess(attestor *Attestor, event cgroupFileEvent) {
	cgroup, ok := c.cgroup(event.CgroupID)
	if !ok {
		return
	}
	process := processInfo(int(event.PID), int(event.HostPID))
	if event.EventType == eventTypeExec {
		if program := cleanCString(event.Path[:]); program != "" {
			process.Program = program
			process.Comm = filepath.Base(program)
		}
	}
	attestor.AddProcess(cgroup, process)
}

func (c *CgroupFileDetector) cgroup(id uint64) (Cgroup, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cgroup, ok := c.cgroups[id]
	return cgroup, ok
}

func loadCgroupFileTracer() (*loadedCgroupFileTracer, error) {
	log.Infof("(%s) loading cgroup-file eBPF tracer", Name)
	spec, err := commandrunbpf.LoadFiletraceSyscall()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	var objs commandrunbpf.FiletraceSyscallObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	links := make([]link.Link, 0, 10)
	for _, tp := range []struct {
		group    string
		name     string
		program  *ebpf.Program
		required bool
	}{
		{"syscalls", "sys_enter_open", objs.TraceOpen, false},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat, true},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2, false},
		{"syscalls", "sys_exit_open", objs.TraceOpenExit, false},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit, true},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit, false},
		{"sched", "sched_process_exec", objs.TraceSchedProcessExec, true},
		{"sched", "sched_process_exit", objs.TraceSchedProcessExit, true},
		{"cgroup", "cgroup_mkdir", objs.TraceCgroupMkdir, true},
		{"syscalls", "sys_enter_mount", objs.TraceMount, true},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.program, nil)
		if err != nil {
			if !tp.required && errors.Is(err, os.ErrNotExist) {
				continue
			}
			closeLinks(links)
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		links = append(links, l)
	}

	log.Infof("(%s) loaded cgroup-file eBPF tracer links=%d", Name, len(links))
	return &loadedCgroupFileTracer{
		events:        objs.Events,
		targetCgroups: objs.TargetCgroups,
		close: func() error {
			closeLinks(links)
			return objs.Close()
		},
	}, nil
}

func (t *loadedCgroupFileTracer) addCgroup(cgroupID uint64) error {
	if t.targetCgroups == nil {
		return fmt.Errorf("target cgroups map is not loaded")
	}
	var enabled uint8 = 1
	return t.targetCgroups.Put(cgroupID, enabled)
}

func processInfo(pid, hostPID int) ProcessInfo {
	if hostPID <= 0 {
		hostPID = pid
	}

	commFile, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", hostPID))
	if err != nil {
		commFile = []byte{}
	}

	cmdLine, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", hostPID))
	if err != nil {
		cmdLine = []byte{}
	}

	return ProcessInfo{
		ProcessID: pid,
		ParentPID: parentPID(hostPID),
		Comm:      strings.TrimSpace(string(commFile)),
		Cmdline:   strings.TrimSpace(string(cmdLine)),
	}
}

func parentPID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 4 {
		return 0
	}
	ppid := 0
	fmt.Sscanf(fields[3], "%d", &ppid)
	return ppid
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
}

// Util Functions.

func decodeEvent(raw []byte) (cgroupFileEvent, error) {
	var event cgroupFileEvent
	eventSize := binary.Size(event)
	if len(raw) != eventSize {
		return event, fmt.Errorf("read workload-run eBPF event: expected %d bytes, got %d", eventSize, len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return event, fmt.Errorf("decode workload-run eBPF event: %w", err)
	}
	return event, nil
}

func cleanCString(data []byte) string {
	data = bytes.TrimLeft(data, "\x00")
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return strings.TrimSpace(string(data))
}

func resolveOpenPath(pid, dfd int, path string) string {
	rootPath := fmt.Sprintf("/proc/%d/root", pid)

	var base string
	switch {
	case filepath.IsAbs(path):
		base = rootPath
		path = strings.TrimPrefix(path, "/")

	case dfd == unix.AT_FDCWD:
		base = fmt.Sprintf("/proc/%d/cwd", pid)

	default:
		base = fmt.Sprintf("/proc/%d/fd/%d", pid, dfd)
	}

	return filepath.Clean(filepath.Join(base, path))
}

func formatCgroupFileTraceError(event cgroupFileEvent) error {
	switch event.Error {
	case errorTypePendingOpenUpdate:
		return fmt.Errorf("workload-run eBPF trace failed to store pending open for pid %d tid %d", event.PID, event.TID)
	case errorTypePendingOpenMissing:
		return fmt.Errorf("workload-run eBPF trace missing pending open for pid %d tid %d", event.PID, event.TID)
	default:
		return fmt.Errorf("workload-run eBPF trace failed to capture opened filename for pid %d tid %d: %d", event.PID, event.TID, event.Error)
	}
}
