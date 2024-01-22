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
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// DepsJsonFileParser is a parser for deps.json file
// see: https://github.com/dotnet/cli/blob/v2.1.400/Documentation/specs/runtime-configuration-file.md
type DepsJsonFileParser struct {
}

// NewDepsJsonFileParser returns a new DepsJsonFileParser
func NewDepsJsonFileParser() *DepsJsonFileParser {
	return &DepsJsonFileParser{}
}

func (g DepsJsonFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.deps.json"}}
}

type dotnetDeps struct {
	Targets map[string]map[string]struct {
		Type         string            `json:"type"`
		Dependencies map[string]string `json:"dependencies"`
	}
	Libraries map[string]struct {
		Type string `json:"type"`
	} `json:"libraries"`
}

func (g DepsJsonFileParser) Parse(path string) ([]model.Package, error) {
	var pkgs []model.Package
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var depsFile dotnetDeps
	if err := decoder.Decode(&depsFile); err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	depTree := collector.NewDependencyTree()
	for nameVer, libInfo := range depsFile.Libraries {
		if libInfo.Type == "package" {
			pkg := parseNameVer(nameVer, path)
			if pkg != nil {
				depTree.AddPackage(pkg)
			}
		}
	}
	for _, deps := range depsFile.Targets {
		for nameVer, libInfo := range deps {
			if libInfo.Type == "package" {
				pkg := parseNameVer(nameVer, path)
				if pkg != nil {
					depTree.AddPackage(pkg)
				}
				for n, v := range libInfo.Dependencies {
					p := newPackage(n, v, path)
					depTree.AddPackage(p)
					depTree.AddDependency(pkg.PURL, p.PURL)
				}
			}
		}
	}
	pkgs = depTree.ToList()
	return pkgs, nil
}

func parseNameVer(nameVer string, sourcePath string) *model.Package {
	var name, version string
	items := strings.Split(nameVer, "/")

	name = items[0]
	if len(items) > 1 {
		version = items[1]
	}
	if name == "" {
		return nil
	}
	return newPackage(name, version, sourcePath)
}
