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

var nameVerReg = regexp.MustCompile(`\s*(".*"\s*,\s*".*")\s*`)

// GemfileParser is a parser for Gemfile file.
// see: https://bundler.io/v2.4/man/gemfile.5.html
type GemfileParser struct{}

// NewGemfileParser returns a new GemfileParser
func NewGemfileParser() *GemfileParser {
	return &GemfileParser{}
}

func (p *GemfileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Gemfile"}}
}

func (p *GemfileParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)
	pkgs := make([]model.Package, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "gem ") {
			pkg := parseGemfileDep(line[4:], path)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
		}
	}
	return pkgs, nil
}

func parseGemfileDep(line string, sourcePath string) *model.Package {
	if strings.Contains(line, ",") {
		nameVer := findSub(nameVerReg, line)
		if len(nameVer) > 0 {
			segs := parseStringArray(nameVer)
			if len(segs) > 1 && len(segs[0]) > 0 {
				return newPackage(segs[0], getVersion(segs[1]), sourcePath)
			}
		}
	} else {
		name := findSubString(strVarReg, line)
		if len(name) > 0 {
			return newPackage(name, "", sourcePath)
		}
	}
	return nil
}
