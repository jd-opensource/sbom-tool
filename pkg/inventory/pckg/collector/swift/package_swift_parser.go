// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package swift

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PackageSwiftParser is a parser for Package.swift
// see: https://www.swift.org/package-manager/
type PackageSwiftParser struct{}

// NewPackageSwiftParser returns a new PackageSwiftParser
func NewPackageSwiftParser() *PackageSwiftParser {
	return &PackageSwiftParser{}
}

func (p *PackageSwiftParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Package.swift"}}
}

func (p *PackageSwiftParser) Parse(path string) ([]model.Package, error) {
	var resolvedFile string
	if strings.HasSuffix(path, ".swift") {
		resolvedFile = path[:len(path)-6] + ".resolved"
	}
	if resolvedFile != "" {
		_, err := os.Stat(resolvedFile)
		if !os.IsNotExist(err) {
			return parsePackageResolvedFile(resolvedFile)
		}
	}
	return parsePackageSwiftFile(path)
}

var packageReg = regexp.MustCompile(`\.package\((\s*url\s*:\s*".*"\s*,.*from\s*:\s".*".*)\)\s*,`)
var urlReg = regexp.MustCompile(`url\s*:\s*"([^"]*)"`)
var fromReg = regexp.MustCompile(`from\s*:\s*"([^"]*)"`)

func parsePackageSwiftFile(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Package.swfit file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)
	pkgs := make([]model.Package, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		items := packageReg.FindStringSubmatch(line)
		if len(items) <= 1 {
			continue
		}
		for i := 1; i < len(items); i++ {
			item := items[i]
			var name, version string
			url := urlReg.FindStringSubmatch(item)
			if len(url) > 1 {
				name = parseImportUrl(url[1])
			}
			from := fromReg.FindStringSubmatch(item)
			if len(from) > 1 {
				version = from[1]
			}
			if name != "" {
				pkg := newPackage(name, version, path)
				pkgs = append(pkgs, pkg)
			}
		}
	}
	// sort packages
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

type PackageResolved struct {
	Object struct {
		Pins []struct {
			Package       string
			RepositoryURL string
			State         struct {
				Branch   string
				Revision string
				Version  string
			}
		}
	}
}

func parsePackageResolvedFile(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Package.resolved file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	resolvedFile := &PackageResolved{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(resolvedFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Package.resolved file: %w", err)
	}
	pkgs := make([]model.Package, 0)
	for i := 0; i < len(resolvedFile.Object.Pins); i++ {
		dep := resolvedFile.Object.Pins[i]

		name := parseImportUrl(dep.RepositoryURL)
		version := dep.State.Version
		if version == "" {
			version = dep.State.Revision
		}
		pkg := newPackage(name, version, path)
		pkgs = append(pkgs, pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, err
}

func parseImportUrl(url string) (name string) {
	name = strings.TrimSpace(url)
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimSuffix(name, ".git")
	return name
}
