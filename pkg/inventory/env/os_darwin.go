// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package env

import (
	"os/exec"
	"strconv"
	"strings"
)

const (
	OSName     = "MacOS"
	KernelName = "Darwin"
)

type version struct {
	name, code string
}

var mapping map[int]version

func init() {
	// https://support.apple.com/zh-cn/HT201260
	mapping = make(map[int]version)
	mapping[22] = version{"macOS", "Ventura"}
	mapping[21] = version{"macOS", "Monterey"}
	mapping[20] = version{"macOS", "Big Sur"}
	mapping[19] = version{"macOS", "Catalina"}
	mapping[18] = version{"macOS", "Mojave"}
	mapping[17] = version{"macOS", "High Sierra"}
	mapping[16] = version{"macOS", "Sierra"}
	mapping[15] = version{"Mac OS X", "El Capitan"}
	mapping[14] = version{"Mac OS X", "Yosemite"}
	mapping[13] = version{"Mac OS X", "Mavericks"}
	mapping[12] = version{"Mac OS X", "Mountain Lion"}
	mapping[11] = version{"Mac OS X", "Lion"}
	mapping[10] = version{"Mac OS X", "Snow Leopard"}
	mapping[9] = version{"Mac OS X", "Leopard"}
	mapping[8] = version{"Mac OS X", "Tiger"}
	mapping[7] = version{"Mac OS X", "Panther"}
	mapping[6] = version{"Mac OS X", "Jaguar"}
	mapping[5] = version{"Mac OS X", "Puma"}
}

func getEnvInfo() Environ {
	kernel, kernelVersion, arch, _ := execUname()

	version, _ := execSWVers()

	osName := OSName
	dotIndex := strings.Index(kernelVersion, ".")
	if dotIndex > -1 {
		kernelNum, err := strconv.Atoi(kernelVersion[:dotIndex])
		if err == nil {
			if ver, ok := mapping[kernelNum]; ok {
				osName = ver.name
			}
		}
	}

	return Environ{
		OS:       osName + " " + version,
		Kernel:   kernel + " " + kernelVersion,
		Arch:     arch,
		Builder:  "",
		Compiler: "",
	}
}

// exec sw_vers -productVersion
func execSWVers() (version string, err error) {
	output, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return
	}
	version = strings.TrimSpace(string(output))
	return
}

const execcount = 2

// exec "uanme -a"
// output: Darwin 22.3.0 arm64
func execUname() (kernel, version, arch string, err error) {
	output, err := exec.Command("uname", "-mrs").Output()

	line := string(output)
	if err != nil {
		return
	}
	segs := strings.Split(strings.TrimSpace(line), " ")
	if len(segs) > 2 {
		kernel = segs[0]
		version = strings.SplitN(segs[1], "-", execcount)[0]
		arch = segs[2]
	}
	return
}
