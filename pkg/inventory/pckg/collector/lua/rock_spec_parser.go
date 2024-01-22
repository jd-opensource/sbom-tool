// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package lua

import (
	"bufio"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/license"
)

// RockSpecParser is a parser for bower.json file.
// see: https://github.com/bower/spec/blob/master/json.md
type RockSpecParser struct{}

// NewRockSpecParser returns a new CartFileParser
func NewRockSpecParser() *RockSpecParser {
	return &RockSpecParser{}
}

func (p *RockSpecParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.rockspec"}}
}

func (p *RockSpecParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(file)
	pkgs := make([]model.Package, 0)
	scanner := bufio.NewScanner(file)

	var name, version, licenseName string
	var depStart bool
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "package =") {
			name = strings.Trim(line[9:], `"' `)
			continue
		} else if strings.HasPrefix(line, "version =") {
			version = strings.Trim(line[9:], `"' `)
			continue
		} else if strings.HasPrefix(line, "license =") {
			licenseName = strings.Trim(line[9:], `"' `)
			continue
		} else if strings.HasPrefix(line, "dependencies =") {
			depStart = true
			continue
		} else if depStart {
			if strings.HasPrefix(line, "}") {
				depStart = false
			} else {
				items := strings.Split(line, ",")
				for _, item := range items {
					pkg := parserDep(item, path)
					if pkg != nil {
						pkgs = append(pkgs, *pkg)
					}
				}
			}
		}
	}
	if name != "" && version != "" {
		mainPkg := newPackage(name, version, path)
		if licenseName != "" {
			value, _, _ := license.ParseLicenseName(licenseName)
			mainPkg.LicenseDeclared = []string{value}
		}

		for i := 0; i < len(pkgs); i++ {
			mainPkg.Dependencies = append(mainPkg.Dependencies, pkgs[i].PURL)
		}
		pkgs = append(pkgs, mainPkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

// parseDep parse dependency like 'lua >= 5.1'
func parserDep(item string, sourcePath string) *model.Package {
	dep := strings.Trim(item, `"'`)
	segs := strings.Split(dep, " ")
	if len(segs) == 0 || segs[0] == "" {
		return nil
	}
	var ver string
	if len(segs) == 3 {
		ver = segs[2]
	} else if len(segs) == 2 {
		ver = segs[1]
	}
	pkg := newPackage(segs[0], ver, sourcePath)
	return &pkg
}
