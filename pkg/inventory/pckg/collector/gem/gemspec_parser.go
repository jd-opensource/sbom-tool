// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package gem

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

const _GemSpecNewStr = "Gem::Specification.new"

var specVarReg = regexp.MustCompile(`Gem::Specification\.new\s*do\s*\|(.*)\|`)
var nameReg = regexp.MustCompile(`.*\.name\s*=(.*)`)
var versionReg = regexp.MustCompile(`.*\.version\s*=(.*)`)
var licenseReg = regexp.MustCompile(`.*\.license\s*=(.*)`)
var licensesReg = regexp.MustCompile(`.*\.licenses\s*=.*\[(.*)].*`)
var dependencyReg = regexp.MustCompile(`.*\.add_dependency(.*)`)
var runtimeDepReg = regexp.MustCompile(`.*\.add_runtime_dependency(.*)`)
var strVarReg = regexp.MustCompile(`['"](.*)['"]`)

// GemSpecParser is a parser for gemspec file.
// see: https://guides.rubygems.org/specification-reference/
type GemSpecParser struct{}

// NewGemSpecParser returns a new NewGemSpecParser
func NewGemSpecParser() *GemSpecParser {
	return &GemSpecParser{}
}

func (p *GemSpecParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.gemspec"}}
}

func (p *GemSpecParser) Parse(path string) ([]model.Package, error) {
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
		if strings.HasPrefix(line, _GemSpecNewStr) {
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
		case strings.HasPrefix(line, newVar+".licenses"):
			ls := findSubStringArray(licensesReg, line)
			if len(ls) > 0 {
				licenses = append(licenses, ls...)
			}
		case strings.HasPrefix(line, newVar+".add_dependency"):
			dep := findSubStringArray(dependencyReg, line)
			if len(dep) == 2 {
				ver := getVersion(dep[1])
				pkgs = append(pkgs, *newPackage(dep[0], ver, path))
			}
		case strings.HasPrefix(line, newVar+".add_runtime_dependency"):
			dep := findSubStringArray(runtimeDepReg, line)
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
