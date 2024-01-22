// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cocoapods

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

const _PodSpecNewStr = "Pod::Spec.new"

var specVarReg = regexp.MustCompile(`Pod::Spec\.new\s*do\s*\|(.*)\|`)
var nameReg = regexp.MustCompile(`.*\.name\s*=(.*)`)
var versionReg = regexp.MustCompile(`.*\.version\s*=(.*)`)
var licenseReg = regexp.MustCompile(`.*\.license\s*=(.*)`)
var dependencyReg = regexp.MustCompile(`.*\.dependency(.*)`)
var strVarReg = regexp.MustCompile(`['"](.*)['"]`)

// PodSpecParser is a parser for podspec file
// see: https://guides.cocoapods.org/syntax/podspec.html
type PodSpecParser struct{}

// NewPodSpecParser returns a new PodSpecParser
func NewPodSpecParser() *PodSpecParser {
	return &PodSpecParser{}
}

func (p *PodSpecParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.podspec"}}
}

func (p *PodSpecParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)
	pkgs := make([]model.Package, 0)
	var newVar, name, version string
	licenses := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, _PodSpecNewStr) {
			newVar = findSub(specVarReg, line)
		}
		if newVar == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, newVar+".name"):
			name = findSubString(nameReg, line)
		case strings.HasPrefix(line, newVar+".version"):
			version = findSubString(versionReg, line)
		case strings.HasPrefix(line, newVar+".license"):
			l := findSubString(licenseReg, line)
			if l != "" {
				licenses = append(licenses, l)
			}
			version = findSubString(versionReg, line)
		case strings.HasPrefix(line, newVar+".dependency"):
			dep := findSubStringArray(dependencyReg, line)
			if len(dep) == 2 {
				ver := getVersion(dep[1])
				pkgs = append(pkgs, *newPackage(dep[0], ver, path))
			}
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", scanner.Err())
	}
	if name != "" && version != "" {
		pkg := newPackage(name, version, path)
		if len(licenses) > 0 {
			pkg.LicenseDeclared = licenses
		}
		pkgs = append(pkgs, *pkg)
	}
	return pkgs, nil
}
