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
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// NuspecFileParser is a parser for nuspec file
// see: https://learn.microsoft.com/en-us/nuget/reference/nuspec
type NuspecFileParser struct {
}

// NewNuspecFileParser returns a new DotnetProjFileParser
func NewNuspecFileParser() *NuspecFileParser {
	return &NuspecFileParser{}
}

func (g NuspecFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.nuspec"}}
}

type nuspec struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		Dependencies struct {
			Dependency []nuspecDep `xml:"dependency"`
			Group      []struct {
				Dependency []nuspecDep `xml:"dependency"`
			} `xml:"group"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

type nuspecDep struct {
	ID          string `xml:"id"`
	IDAttr      string `xml:"id,attr"`
	Version     string `xml:"version"`
	VersionAttr string `xml:"version,attr"`
}

func (g NuspecFileParser) Parse(path string) ([]model.Package, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s : %w", path, err)
	}
	defer file.Close()
	var content nuspec
	if err := xml.NewDecoder(file).Decode(&content); err != nil {
		return nil, fmt.Errorf("failed to decode file %s : %w", path, err)
	}

	depTree := collector.NewDependencyTree()
	for _, dep := range content.Metadata.Dependencies.Dependency {
		pkg := parseNuspecDep(dep, path)
		if pkg != nil {
			depTree.AddPackage(pkg)
		}
	}

	for _, group := range content.Metadata.Dependencies.Group {
		for _, dep := range group.Dependency {
			pkg := parseNuspecDep(dep, path)
			if pkg != nil {
				depTree.AddPackage(pkg)
			}
		}
	}

	pkgs := depTree.ToList()
	return pkgs, nil
}

func parseNuspecDep(dep nuspecDep, sourcePath string) *model.Package {
	name := dep.ID
	if name == "" {
		name = dep.IDAttr
	}
	version := dep.Version
	if version == "" {
		version = dep.VersionAttr
	}
	if name == "" || strings.Contains(name, "$") {
		return nil
	}
	if strings.Contains(version, "$") {
		version = ""
	}
	return newPackage(name, version, sourcePath)
}
