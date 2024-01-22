// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conan

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

type Result struct {
	Nodes []Pkg `json:"nodes"`
}

type Pkg struct {
	Ref     string `json:"ref"`
	License string `json:"license"`
}

// getConanPkgLicense get conanfile.txt license by conan graph info
func getConanPkgLicense(path string) (map[string]string, error) {
	var result Result
	licenseMap := make(map[string]string)

	cmds := []string{
		"graph",
		"info",
		path,
		"--format=json",
		"--filter=license",
	}

	output, err := exec.Command("conan", cmds...).Output()
	if err != nil {
		log.Warnf("skip! exec conan err: " + err.Error())
		return licenseMap, err
	}

	if err := json.Unmarshal(output, &result); err != nil {
		log.Warnf("skip! exec conan result json parse error: " + err.Error())
	}

	for _, node := range result.Nodes {
		if node.Ref == "conanfile" {
			continue
		}

		licenseMap[strings.Split(node.Ref, "#")[0]] = node.License
	}
	return licenseMap, nil
}

func resolveLicense(name string, version string, licenses map[string]string) []string {
	licenseList := make([]string, 0)
	key := fmt.Sprintf("%s/%s", name, version)
	if _, ok := licenses[key]; ok {
		licenseList = append(licenseList, licenses[key])
	}
	return licenseList
}
