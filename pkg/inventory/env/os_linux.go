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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

const (
	KernelName = "Linux"
)

func getEnvInfo() Environ {
	name, version, err := execLsbRelease()
	if err != nil {
		name, version, err = parseLsbRelease()
		if err != nil {
			name, version, _ = parseOsRelease()
		}
	}
	kernel, kernelVersion, arch, _ := execUname()

	return Environ{
		OS:       name + " " + version,
		Kernel:   kernel + " " + kernelVersion,
		Arch:     arch,
		Builder:  "",
		Compiler: "",
	}
}

// exec lsb_release -a
// Distributor ID ： Ubuntu
// Release : 22.04
// result: Ubuntu 22.04.
func execLsbRelease() (name, version string, err error) {
	cmd := exec.Command("lsb_release", "-a")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	result := parseContent(string(output), ":")
	name = result["Distributor ID"]
	version = result["Release"]

	return
}

// parse /etc/lsb_relase
// DISTRIB_ID ： Ubuntu
// DISTRIB_RELEASE : 22.04
// result: Ubuntu 22.04.
func parseLsbRelease() (name, version string, err error) {
	file := "/etc/lsb-release"
	_, err = os.Stat(file)
	if err != nil {
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	result := parseContent(string(data), "=")
	name = result["DISTRIB_ID"]
	version = result["DISTRIB_RELEASE"]

	return
}

// parse /etc/os-release.
func parseOsRelease() (name, version string, err error) {
	file := "/etc/os-release"
	_, err = os.Stat(file)
	if err != nil {
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	result := parseContent(string(data), "=")
	name = result["ID"]
	version = result["VERSION_ID"]

	return
}

const kysegcount = 2

// parse kv pair
// K : V
// return map[string]string.
func parseContent(content string, seg string) map[string]string {
	lines := strings.Split(content, "\n")
	result := make(map[string]string)
	for _, line := range lines {
		if strings.Contains(line, seg) {
			kv := strings.SplitN(line, seg, kysegcount)
			k := strings.TrimSpace(kv[0])
			v := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			result[k] = v
		}
	}

	return result
}

const unamecount = 3

// exec uanme -a
// output: Linux 4.4.162-94.69-default x86_64
func execUname() (kernel, version, arch string, err error) {
	cmd := exec.Command("uname", "-mrs")
	output, err := cmd.Output()
	line := string(output)
	if err != nil {
		return
	}
	segs := strings.Split(strings.TrimSpace(line), " ")
	if len(segs) >= unamecount {
		kernel = segs[0]
		version = strings.Split(segs[1], "-")[0]
		arch = segs[2]
	}

	return
}
