// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package nuget

import (
	"encoding/json"
	"fmt"
	"os"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PackagesLockJsonFileParser is a parser for packages.lock.json file
// see: https://learn.microsoft.com/zh-cn/nuget/reference/packages-config
type PackagesLockJsonFileParser struct {
}

// NewPackagesLockJsonFileParser returns a new PackagesLockJsonFileParser
func NewPackagesLockJsonFileParser() *PackagesLockJsonFileParser {
	return &PackagesLockJsonFileParser{}
}

func (g PackagesLockJsonFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"packages.lock.json"}}
}

type packageLock struct {
	Dependencies map[string]map[string]struct {
		Type         string            `json:"type"`
		Resolved     string            `json:"resolved"`
		Dependencies map[string]string `json:"dependencies"`
	}
}

func (g PackagesLockJsonFileParser) Parse(path string) ([]model.Package, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var lockFile packageLock
	err = json.NewDecoder(file).Decode(&lockFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file: %w", err)
	}

	depTree := collector.NewDependencyTree()
	for _, deps := range lockFile.Dependencies {
		for name, dep := range deps {
			pkg := newPackage(name, dep.Resolved, path)
			depTree.AddPackage(pkg)
			for n, v := range dep.Dependencies {
				p := newPackage(n, v, path)
				depTree.AddDependency(pkg.PURL, p.PURL)
			}
		}
	}

	pkgs := depTree.ToList()
	return pkgs, nil
}
