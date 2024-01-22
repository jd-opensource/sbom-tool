// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package golang

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// GoModGraphParser is a parser for output of executing 'go mod graph' command
// see: https://go.dev/ref/mod#go-mod-graph
type GoModGraphParser struct{}

// NewGoModGraphParser returns a new GoModGraphParser
func NewGoModGraphParser() *GoModGraphParser {
	return &GoModGraphParser{}
}

func (p *GoModGraphParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"go-mod-graph", "go-mod-graph.txt"}}
}

func (p *GoModGraphParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GoModGraphParser file path: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Podfile file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)

	pkgMap := make(map[string]*model.Package)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		items := strings.Split(line, " ")
		if len(items) < 2 {
			continue
		}
		modName, modVer := parseGoMod(items[0])
		depName, depVer := parseGoMod(items[1])

		mod := newPackage(modName, modVer, path)
		dep := newPackage(depName, depVer, path)

		if modPkg, found := pkgMap[mod.PURL]; found {
			if !slices.Contains(modPkg.Dependencies, dep.PURL) {
				modPkg.Dependencies = append(modPkg.Dependencies, dep.PURL)
			}
		} else {
			pkgMap[mod.PURL] = mod
		}
		if _, found := pkgMap[dep.PURL]; !found {
			pkgMap[dep.PURL] = dep
		}
	}
	pkgs := make([]model.Package, 0)
	for _, pkg := range pkgMap {
		sort.Strings(pkg.Dependencies)
		pkgs = append(pkgs, *pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func parseGoMod(mod string) (name, version string) {
	items := strings.SplitN(strings.TrimSpace(mod), "@", 2)
	name = items[0]
	if len(items) > 1 {
		version = items[1]
	}
	return
}
