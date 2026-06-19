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

// Enrich marks workloads that were accepted by the Docker/containerd filters.
func (DockerProvider) Enrich(_ context.Context, workload *Workload) error {
	if workload.Metadata == nil {
		workload.Metadata = make(map[string]string)
	}
	for _, cgroup := range workload.Cgroups {
		workload.Runtime = dockerRuntime(cgroup.Path)
	}
	workload.Metadata["collector.cgroup-file"] = "ebpf"
	workload.Metadata["provider.docker"] = "matched"
	return nil
}

// CgroupFilter accepts cgroups created by Docker or containerd.
func (DockerProvider) CgroupFilter(cgroupPath string) bool {
	return dockerRuntime(cgroupPath) != ""
}

// FileFilter accepts all files under a previously accepted Docker/containerd cgroup.
func (DockerProvider) FileFilter(_ string) bool {
	return true
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
