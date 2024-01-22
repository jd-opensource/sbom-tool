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
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

const (
	OS_Name     = "Windows"
	Kernel_Name = "WindowNT"
)

func getEnvInfo() Environ {
	windows.GetVersion()
	verInfo := windows.RtlGetVersion()

	kernelVersion := fmt.Sprintf("%d.%d", verInfo.MajorVersion, verInfo.MinorVersion)
	var osEdition string
	// https://docs.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
	switch kernelVersion {
	case "10.0": // 10
		if verInfo.BuildNumber >= 22000 {
			osEdition = "11"
		} else {
			osEdition = "10"
		}
	case "6.3": // Server 2012 R2
		osEdition = "8.1"
	case "6.2": // Server 2012
		osEdition = "8"
	case "6.1":
		osEdition = "7"
	case "6.0":
		osEdition = "Vista"
	case "5.2":
		osEdition = "Server 2003"
	case "5.1":
		osEdition = "XP"
	case "5.0":
		osEdition = "2000"
	}

	return Environ{
		OS:       OS_Name + " " + osEdition,
		Kernel:   Kernel_Name + " " + kernelVersion,
		Arch:     runtime.GOARCH,
		Builder:  "",
		Compiler: "",
	}
}
