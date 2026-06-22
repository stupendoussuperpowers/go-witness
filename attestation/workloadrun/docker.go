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
	"strings"
)

func init() {
	Providers["docker"] = func() Provider {
		return DockerProvider{}
	}
}

type DockerProvider struct{}

func (DockerProvider) Name() string {
	return "docker"
}

// Enrich labels docker/containerd workloads after collection is complete.
func (DockerProvider) Enrich(_ context.Context, workloads []Workload) ([]Workload, error) {
	for i := range workloads {
		for _, cgroup := range workloads[i].Cgroups {
			runtime := dockerRuntime(cgroup.Path)
			if runtime == "" {
				continue
			}
			workloads[i].Runtime = runtime
			if workloads[i].Metadata == nil {
				workloads[i].Metadata = make(map[string]string)
			}
			workloads[i].Metadata["provider"] = "docker"
		}
	}
	return workloads, nil
}

// These are provider specific filters which mark which mounts/cgroups/file opens
// are of interest to this specific provider.
func (DockerProvider) CgroupFilter(cgroupPath string) bool {
	return dockerRuntime(cgroupPath) != ""
}

func (DockerProvider) FileFilter(_ string) bool {
	return true
}

func (DockerProvider) MountFilter(mount Mount) bool {
	// Reject all mounts for now.
	return false
}

func dockerRuntime(cgroupPath string) string {
	path := strings.ToLower(cgroupPath)
	switch {
	case strings.Contains(path, "docker"):
		return "docker"
	case strings.Contains(path, "containerd"):
		return "containerd"
	default:
		return ""
	}
}
