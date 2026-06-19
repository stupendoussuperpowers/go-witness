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

//go:build !linux

package workloadrun

import (
	"context"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
)

type CgroupFileDetector struct{}

func NewCgroupFileDetector() *CgroupFileDetector {
	return &CgroupFileDetector{}
}

func (c *CgroupFileDetector) Name() string {
	return "cgroup-file"
}

func (c *CgroupFileDetector) Start(ctx context.Context, attestor *Attestor, hash []cryptoutil.DigestValue) error {
	return fmt.Errorf("cgroup-file collector is only supported on linux")
}

func (c *CgroupFileDetector) Stop() error {
	return nil
}
