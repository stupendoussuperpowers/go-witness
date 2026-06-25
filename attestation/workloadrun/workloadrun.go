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

package workloadrun

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "workload-run"
	Type    = "https://witness.dev/attestations/workload-run/v0.1"
	RunType = attestation.ExecuteRunType
)

var (
	_ attestation.Attestor            = &Attestor{}
	_ attestation.ExecuteHookDeclarer = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(
		Name,
		Type,
		RunType,
		func() attestation.Attestor { return New() },
		registry.StringSliceConfigOption[attestation.Attestor](
			"provider",
			"Workload metadata providers to enable",
			[]string{},
			func(a attestation.Attestor, names []string) (attestation.Attestor, error) {
				attestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a workload-run attestor", a)
				}
				WithProviderNames(names...)(attestor)
				return attestor, nil
			},
		),
	)
}

type Option func(*Attestor)

// Provider decides which detected workload events are relevant and may add
// provider-specific metadata or grouping after collection is complete.
type Provider interface {
	Name() string
	CgroupFilter(cgroup string) bool
	FileFilter(files string) bool
	MountFilter(mount Mount) bool
	Enrich(ctx context.Context, workloads []Workload) ([]Workload, error)
}

type ProviderFactory func() Provider

var Providers = map[string]ProviderFactory{}

// WithProviderNames appends named providers from the package registry.
func WithProviderNames(names ...string) Option {
	return func(a *Attestor) {
		for _, name := range names {
			factory, ok := Providers[name]
			if !ok {
				a.optionErrors = append(a.optionErrors, fmt.Errorf("workload provider %q is not registered", name))
				continue
			}

			if !slices.Contains(a.providers, factory()) {
				a.providers = append(a.providers, factory())
			}
		}
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		detector:  NewCgroupFileDetector(),
		providers: []Provider{DockerProvider{}},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

type Attestor struct {
	WorkloadRun WorkloadRun `json:"workload_run"`

	hooks        *attestation.ExecuteHooks
	detector     *CgroupFileDetector
	providers    []Provider
	optionErrors []error
	mu           sync.Mutex
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&WorkloadRun{})
}

// IsExperimental keeps workload-run behind the experimental CLI gate.
func (a *Attestor) IsExperimental() bool {
	return true
}

func (a *Attestor) DeclareHooks(hooks *attestation.ExecuteHooks) error {
	if err := hooks.Declare(Name, attestation.StagePreExec); err != nil {
		return err
	}
	if err := hooks.Declare(Name, attestation.StagePreExit); err != nil {
		return err
	}
	a.hooks = hooks
	return nil
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if len(a.optionErrors) > 0 {
		return a.optionErrors[0]
	}
	if a.hooks == nil {
		return fmt.Errorf("%s requires execute hooks", Name)
	}

	runCtx, cancel := context.WithCancel(ctx.Context())
	defer cancel()

	shutdown := make(chan struct{})
	if err := a.registerHooks(runCtx, ctx.Hashes(), cancel, shutdown); err != nil {
		return err
	}

	select {
	case <-shutdown:
	case <-ctx.Context().Done():
		return ctx.Context().Err()
	}

	a.mu.Lock()
	workloads := append([]Workload(nil), a.WorkloadRun.Workloads...)
	a.mu.Unlock()

	var err error
	for _, provider := range a.providers {
		workloads, err = provider.Enrich(ctx.Context(), workloads)
		if err != nil {
			return fmt.Errorf("provider %q enrich workloads: %w", provider.Name(), err)
		}
	}

	a.mu.Lock()
	a.WorkloadRun.Workloads = workloads
	a.mu.Unlock()

	return nil
}

func (a *Attestor) registerHooks(ctx context.Context, hashes []cryptoutil.DigestValue, cancel context.CancelFunc, shutdown chan<- struct{}) error {
	preExecReady, err := a.hooks.RegisterHook(attestation.StagePreExec, Name, func(pid int) error {
		log.Debugf("(%s) pre-exec hook triggered for pid %d", Name, pid)

		a.mu.Lock()
		a.WorkloadRun.Scope.StartedAt = time.Now()
		a.WorkloadRun.Scope.Trigger = Trigger{Attestor: "command-run", ProcessID: pid}
		a.WorkloadRun.Providers = providerNames(a.providers)
		a.WorkloadRun.Collectors = []string{a.detector.Name()}
		a.mu.Unlock()

		if err := a.detector.Start(ctx, a, hashes); err != nil {
			return fmt.Errorf("start %q: %w", a.detector.Name(), err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	close(preExecReady)

	preExitReady, err := a.hooks.RegisterHook(attestation.StagePreExit, Name, func(pid int) error {
		log.Debugf("(%s) pre-exit hook triggered for pid %d", Name, pid)
		cancel()

		log.Infof("(%s) stopping %q", Name, a.detector.Name())
		stopErr := a.detector.Stop()
		log.Infof("(%s) stopped %q", Name, a.detector.Name())

		a.mu.Lock()
		a.WorkloadRun.Scope.EndedAt = time.Now()
		a.mu.Unlock()

		close(shutdown)
		return stopErr
	})
	if err != nil {
		return err
	}
	close(preExitReady)
	return nil
}

func providerNames(providers []Provider) []string {
	names := make([]string, 0, len(providers))
	for _, provider := range providers {
		names = append(names, provider.Name())
	}
	return names
}

// AcceptCgroup returns true when at least one provider wants this cgroup.
func (a *Attestor) AcceptCgroup(path string) bool {
	for _, provider := range a.providers {
		if provider.CgroupFilter(path) {
			return true
		}
	}
	log.Debugf("Excluding cgroup: %s", path)
	return false
}

// AcceptFile returns true when at least one provider wants this opened file.
func (a *Attestor) AcceptFile(path string) bool {
	for _, provider := range a.providers {
		if provider.FileFilter(path) {
			return true
		}
	}
	return false
}

// AcceptMount returns true when at least one provider wants this mount event.
func (a *Attestor) AcceptMount(mount Mount) bool {
	for _, provider := range a.providers {
		if provider.MountFilter(mount) {
			return true
		}
	}
	log.Debugf("Excluding mount: %s", mount.Directory)
	return false
}

// AddCgroup creates one default workload for each detected cgroup.
func (a *Attestor) AddCgroup(cgroup Cgroup) {
	a.updateWorkload(workloadID(cgroup), func(workload *Workload) {
		workload.Kind = "cgroup"

		for _, item := range workload.Cgroups {
			if item.ID == cgroup.ID && item.Path == cgroup.Path {
				return
			}
		}

		workload.Cgroups = append(workload.Cgroups, cgroup)
	})
}

// AddMount records a mount event under the cgroup workload that emitted it.
func (a *Attestor) AddMount(cgroup Cgroup, mount Mount) {
	a.updateWorkload(workloadID(cgroup), func(workload *Workload) {
		for _, item := range workload.Mounts {
			if item == mount {
				return
			}
		}
		workload.Mounts = append(workload.Mounts, mount)
	})
}

// AddProcess records process metadata under the cgroup workload.
func (a *Attestor) AddProcess(cgroup Cgroup, process ProcessInfo) {
	a.updateWorkload(workloadID(cgroup), func(workload *Workload) {
		for _, item := range workload.Processes {
			if item.ProcessID == process.ProcessID {
				return
			}
		}
		workload.Processes = append(workload.Processes, process)

	})
}

// AddOpenedFile records a path immediately, then upgrades it with a digest later.
func (a *Attestor) AddOpenedFile(cgroup Cgroup, path string, digest cryptoutil.DigestSet) {
	a.updateWorkload(workloadID(cgroup), func(workload *Workload) {
		if workload.OpenedFiles == nil {
			workload.OpenedFiles = make(map[string]cryptoutil.DigestSet)
		}
		if digest == nil && workload.OpenedFiles[path] != nil {
			return
		}
		workload.OpenedFiles[path] = digest
	})
}

func (a *Attestor) updateWorkload(id string, update func(*Workload)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	workload := a.workloadLocked(id)
	if update != nil {
		update(workload)
	}
}

func (a *Attestor) workloadLocked(id string) *Workload {
	for i := range a.WorkloadRun.Workloads {
		if a.WorkloadRun.Workloads[i].ID == id {
			return &a.WorkloadRun.Workloads[i]
		}
	}
	a.WorkloadRun.Workloads = append(a.WorkloadRun.Workloads, Workload{
		ID:          id,
		OpenedFiles: make(map[string]cryptoutil.DigestSet),
	})
	return &a.WorkloadRun.Workloads[len(a.WorkloadRun.Workloads)-1]
}

func workloadID(cgroup Cgroup) string {
	return "cgroup:" + cgroup.Path
}
