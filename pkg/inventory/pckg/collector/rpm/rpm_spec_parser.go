// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package rpm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

const _BuildRequiresPrefix = "BuildRequires:"
const _BuildRequiresPrefixLength = 14

// RPMSpecFileParser is a parser for rpm spec file
// see: https://rpm-packaging-guide.github.io/#what-is-a-spec-file
type RPMSpecFileParser struct{}

// NewRPMSpecFileParser returns a new RPMSpecFileParser
func NewRPMSpecFileParser() *RPMSpecFileParser {
	return &RPMSpecFileParser{}
}

func (p *RPMSpecFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.spec"}}
}

func (p *RPMSpecFileParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	reader := bufio.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}
	pkgs := make([]model.Package, 0)
	for {
		line, err := reader.ReadString('\n')
		if line == "" && err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return nil, fmt.Errorf("failed to read line : %w", err)
			}
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, _BuildRequiresPrefix) {
			p, err := parseBuildRequires(line[_BuildRequiresPrefixLength:], path)
			if err == nil {
				pkgs = append(pkgs, p...)
			}
		}
	}

	// sort packages
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

var operators = []string{"=", ">", "<", ">=", "<="}

func parseBuildRequires(requires string, sourcePath string) ([]model.Package, error) {
	requires = strings.TrimSpace(requires)
	requires = strings.ReplaceAll(requires, ",", " ")
	segs := strings.Split(requires, " ")
	length := len(segs)
	name := ""
	op := ""
	pkgs := make([]model.Package, 0)
	for i := 0; i < length; i++ {
		seg := strings.TrimSpace(segs[i])
		if seg == "" {
			continue
		} else if slices.Contains(operators, seg) {
			op = seg
		} else if op != "" {
			pkgs = append(pkgs, newPackage(name, seg, sourcePath))
			name = ""
			op = ""
		} else {
			if name != "" {
				pkgs = append(pkgs, newPackage(name, "", sourcePath))
			}
			name = seg
			if i == length-1 {
				pkgs = append(pkgs, newPackage(name, "", sourcePath))
			}
		}
	}
	return pkgs, nil
}
