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
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

// DotnetProjFileParser is a parser for msbuild project file
// see: https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-project-file-schema-reference?view=vs-2022#msbuild-xml-schema-elements
//
//	https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files
type DotnetProjFileParser struct {
}

// NewDotnetProjFileParser returns a new DotnetProjFileParser
func NewDotnetProjFileParser() *DotnetProjFileParser {
	return &DotnetProjFileParser{}
}

func (g DotnetProjFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.csproj", "*.vbproj", "*.fsproj", "*.vcproj"}}
}

type projObj struct {
	XMLName    xml.Name `xml:"Project"`
	ItemGroups []struct {
		PackageReferences []projPackage `xml:"PackageReference"`
	} `xml:"ItemGroup"`
	Targets []struct {
		ItemGroups []struct {
			PackageReferences []projPackage `xml:"PackageReference"`
		} `xml:"ItemGroup"`
	} `xml:"Target"`
}

type projPackage struct {
	Include     string `xml:"Include"`
	IncludeAttr string `xml:"Include,attr"`
	Version     string `xml:"Version"`
	VersionAttr string `xml:"Version,attr"`
}

func (g DotnetProjFileParser) Parse(path string) ([]model.Package, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s : %w", path, err)
	}
	defer file.Close()
	var content projObj
	if err := xml.NewDecoder(file).Decode(&content); err != nil {
		return nil, fmt.Errorf("failed to decode file %s : %w", path, err)
	}

	depTree := collector.NewDependencyTree()
	for _, group := range content.ItemGroups {
		for _, ref := range group.PackageReferences {
			pkg := parseProjPackage(ref, path)
			if pkg != nil {
				depTree.AddPackage(pkg)
			}
		}
	}
	for _, target := range content.Targets {
		for _, group := range target.ItemGroups {
			for _, ref := range group.PackageReferences {
				pkg := parseProjPackage(ref, path)
				if pkg != nil {
					depTree.AddPackage(pkg)
				}
			}
		}
	}

	pkgs := depTree.ToList()
	return pkgs, nil
}

func parseProjPackage(ref projPackage, sourcePath string) *model.Package {
	name := ref.Include
	if name == "" {
		name = ref.IncludeAttr
	}
	version := ref.Version
	if version == "" {
		version = ref.VersionAttr
	}
	if name == "" || isIncludePath(name) {
		return nil
	}
	return newPackage(name, version, sourcePath)
}

func isIncludePath(include string) bool {
	return strings.Contains(include, `\`) ||
		util.SliceAny([]string{".csproj", ".vbproj", ".fsproj", ".vcproj"}, func(s string) bool {
			return strings.HasSuffix(include, s)
		})
}
