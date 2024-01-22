// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build !windows && !darwin && !linux && !freebsd && !openbsd && !dragonfly && !netbsd
// +build !windows,!darwin,!linux,!freebsd,!openbsd,!dragonfly,!netbsd

package env

import (
	"runtime"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// copy from go/build/syslist.go
var unixOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

func getEnvInfo() Environ {
	os := runtime.GOOS
	arch := runtime.GOARCH
	kernel := ""
	if slices.Contains(maps.Keys(unixOS), os) {
		kernel = "Unix"
	}
	return Environ{
		OS:       os,
		Arch:     arch,
		Kernel:   kernel,
		Builder:  "",
		Compiler: "",
	}
}
