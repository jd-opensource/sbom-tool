// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package carthage

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

// CartFileParser is a parser for Cartfile file
// see: https://github.com/Carthage/Carthage
//
//	https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile
type CartFileParser struct{}

// NewCartFileParser returns a new CartFileParser
func NewCartFileParser() *CartFileParser {
	return &CartFileParser{}
}

func (p *CartFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Cartfile"}}
}

func (p *CartFileParser) Parse(path string) ([]model.Package, error) {
	resolvedFile := path + ".resolved"
	_, err := os.Stat(resolvedFile)
	if !os.IsNotExist(err) {
		return parseFile(resolvedFile)
	} else {
		return parseFile(path)
	}
}

func parseFile(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Podfile file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)
	pkgs := make([]model.Package, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !util.SliceAny([]string{"github ", "git ", "binary "}, func(prefix string) bool {
			return strings.HasPrefix(line, prefix)
		}) {
			continue
		}

		items := strings.SplitN(line, " ", 3)
		if len(items) < 3 {
			continue
		}
		// github / git / binary
		origin := items[0]
		// "ReactiveCocoa/ReactiveCocoa"
		name := strings.Trim(items[1], `'"`)
		// ~> 1.0    # (1.0 or later, but less than 2.0)
		version := strings.Trim(strings.SplitN(items[2], "#", 2)[0], `^~>=<"' `)

		switch origin {
		case "github":
			name = parseImportUrl(name)
		case "git", "binary":
			// excludes file:
			if util.SliceAny([]string{"https://", "http://"}, func(s string) bool {
				return strings.HasPrefix(name, s)
			}) {
				name = parseImportUrl(name)
			} else {
				continue
			}
		}
		pkg := newPackage(name, version, path)
		pkgs = append(pkgs, pkg)
	}

	// sort packages
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func parseImportUrl(url string) (name string) {
	name = strings.TrimSpace(url)
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimSuffix(name, ".git")
	return name
}
