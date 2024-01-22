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

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PackagesConfigFileParser is a parser for packages.json file
// see: https://learn.microsoft.com/zh-cn/nuget/reference/packages-config
type PackagesConfigFileParser struct {
}

// NewPackagesConfigFileParser returns a new PackagesConfigFileParser
func NewPackagesConfigFileParser() *PackagesConfigFileParser {
	return &PackagesConfigFileParser{}
}

func (g PackagesConfigFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"packages.json"}}
}

func (g PackagesConfigFileParser) Parse(path string) ([]model.Package, error) {
	var pkgs []model.Package
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s : %w", path, err)
	}
	defer file.Close()
	var content packagesConfigContent
	if err := xml.NewDecoder(file).Decode(&content); err != nil {
		return nil, fmt.Errorf("failed to decode file %s : %w", path, err)
	}

	for _, pkg := range content.Packages {
		if pkg.ID == "" || pkg.DevDependency {
			continue
		}

		lib := newPackage(pkg.ID, pkg.Version, path)
		pkgs = append(pkgs, *lib)
	}

	// sort packages
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

type configPackageReference struct {
	XMLName         xml.Name `xml:"package"`
	TargetFramework string   `xml:"targetFramework,attr"`
	Version         string   `xml:"version,attr"`
	DevDependency   bool     `xml:"developmentDependency,attr"`
	ID              string   `xml:"id,attr"`
}

type packagesConfigContent struct {
	XMLName  xml.Name                 `xml:"packages"`
	Packages []configPackageReference `xml:"package"`
}
