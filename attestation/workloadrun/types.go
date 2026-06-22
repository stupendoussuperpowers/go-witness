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
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
)

type WorkloadRun struct {
	Providers  []string   `json:"providers,omitempty"`
	Collectors []string   `json:"collectors,omitempty"`
	Scope      Scope      `json:"scope,omitempty"`
	Workloads  []Workload `json:"workloads,omitempty"`
}

type Scope struct {
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Trigger   Trigger   `json:"trigger,omitempty"`
}

type Trigger struct {
	Attestor  string `json:"attestor,omitempty"`
	ProcessID int    `json:"processid,omitempty"`
}

type Workload struct {
	ID          string                          `json:"id,omitempty"`
	Kind        string                          `json:"kind,omitempty"`
	Runtime     string                          `json:"runtime,omitempty"`
	Name        string                          `json:"name,omitempty"`
	Image       string                          `json:"image,omitempty"`
	Cgroups     []Cgroup                        `json:"cgroups,omitempty"`
	Mounts      []Mount                         `json:"mounts,omitempty"`
	Processes   []ProcessInfo                   `json:"processes,omitempty"`
	OpenedFiles map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	Metadata    map[string]string               `json:"metadata,omitempty"`
}

type Cgroup struct {
	ID   uint64 `json:"id,omitempty"`
	Path string `json:"path,omitempty"`
}

type Mount struct {
	Device     string `json:"device,omitempty"`
	Directory  string `json:"directory,omitempty"`
	Type       string `json:"type,omitempty"`
	Data       string `json:"data,omitempty"`
	Flags      uint64 `json:"flags,omitempty"`
	ProcessID  int    `json:"processid,omitempty"`
	HostPID    int    `json:"hostpid,omitempty"`
	HostTID    int    `json:"hosttid,omitempty"`
	CgroupID   uint64 `json:"cgroupid,omitempty"`
	CgroupPath string `json:"cgrouppath,omitempty"`
}

type ProcessInfo struct {
	Program          string               `json:"program,omitempty"`
	ProcessID        int                  `json:"processid"`
	ParentPID        int                  `json:"parentpid"`
	ProgramDigest    cryptoutil.DigestSet `json:"programdigest,omitempty"`
	Comm             string               `json:"comm,omitempty"`
	Cmdline          string               `json:"cmdline,omitempty"`
	ExeDigest        cryptoutil.DigestSet `json:"exedigest,omitempty"`
	Environ          string               `json:"environ,omitempty"`
	SpecBypassIsVuln bool                 `json:"specbypassisvuln,omitempty"`
}
