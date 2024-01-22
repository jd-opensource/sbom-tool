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
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

var headers = []string{"PATH", "GIT", "GEM"}

// GemFileLockParser is a parser for Gemfile.lock file.
// see: https://bundler.io/v2.4/man/bundle-lock.1.html
type GemFileLockParser struct{}

// NewGemFileLockParser returns a new GemFileLockParser
func NewGemFileLockParser() *GemFileLockParser {
	return &GemFileLockParser{}
}

func (p *GemFileLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Gemfile.lock"}}
}

func (p *GemFileLockParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)

	lines := parseLines(scanner)

	depTree := collector.NewDependencyTree()
	depMap := make(map[string][]string)
	count := len(lines)
	for i := 0; i < count; i++ {
		line := lines[i]
		trimLine := strings.TrimSpace(line)
		if isPkg(line) {
			segs := strings.SplitN(trimLine, " ", 2)
			if len(segs) == 2 {
				name := segs[0]
				ver := strings.Trim(segs[1], "()")
				pkg := newPackage(name, ver, path)
				depTree.AddPackage(pkg)
				deps := make([]string, 0)
				scanLines := 0
				for j := i + 1; j < count; j++ {
					if isDep(lines[j]) {
						dep := strings.SplitN(strings.TrimSpace(lines[j]), " ", 2)[0]
						deps = append(deps, dep)
						scanLines++
					} else if isPkg(lines[j]) {
						break
					}

				}
				i = i + scanLines
				if len(deps) > 0 {
					depMap[pkg.PURL] = deps
				}
			}
		}
	}

	for purl, deps := range depMap {
		pkg := depTree.GetPackage(purl)
		if pkg != nil {
			for _, dep := range deps {
				pkgs := depTree.GetPackagesByName(dep)
				if len(pkgs) > 0 {
					depTree.AddDependency(purl, pkgs[0].PURL)
				}
			}
		}
	}
	pkgs := depTree.ToList()

	return pkgs, nil
}

func parseLines(scanner *bufio.Scanner) []string {
	lines := make([]string, 0)
	var header string
	var specs bool
	for scanner.Scan() {
		line := scanner.Text()
		trimLine := strings.TrimSpace(line)
		if trimLine == "" {
			continue
		}
		if line[0] != ' ' {
			header = ""
			specs = false
			if slices.Contains(headers, trimLine) {
				header = trimLine
			}
			continue
		}

		if header != "" && trimLine == "specs:" {
			specs = true
		}
		if header == "" || !specs {
			continue
		}
		if isPkg(line) || isDep(line) {
			lines = append(lines, line)
		}
	}
	return lines
}

func isPkg(line string) bool {
	return len(line) > 5 && strings.Count(line[:5], " ") == 4
}

func isDep(line string) bool {
	return len(line) > 7 && strings.Count(line[:7], " ") == 6
}
