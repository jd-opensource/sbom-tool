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

import "fmt"

type Environ struct {
	OS       string
	Arch     string
	Kernel   string
	Compiler string
	Builder  string
}

// GetEnvInfo returns the environment information.
func GetEnvInfo() Environ {
	return getEnvInfo()
}

func (e Environ) String() string {
	return fmt.Sprintf("[OS=%s,Arch=%s,Kernel=%s,Compiler=%s,Builder=%s]", e.OS, e.Arch, e.Kernel, e.Compiler, e.Builder)
}
