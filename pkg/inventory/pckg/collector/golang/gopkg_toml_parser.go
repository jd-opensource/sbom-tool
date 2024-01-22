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
	"os"
	"strings"

	"github.com/pelletier/go-toml"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// GopkgTOMLParser is a parser for Gopkg.toml file.
// see: https://github.com/golang/dep/blob/master/docs/Gopkg.toml.md
type GopkgTOMLParser struct{}

// NewGopkgTOMLParser returns a new GopkgTOMLParser
func NewGopkgTOMLParser() *GopkgTOMLParser {
	return &GopkgTOMLParser{}
}

func (p *GopkgTOMLParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Gopkg.toml"}}
}

// see https://golang.github.io/dep/docs/Gopkg.toml.html
type gopkgToml struct {
	Constraints []gopkgDep `toml:"constraint"`
	Overrides   []gopkgDep `toml:"overrides"`
}

// see https://golang.github.io/dep/docs/Gopkg.lock.html
type gopkgLock struct {
	Project []gopkgDep `toml:"projects"`
}

type gopkgDep struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Revision string `toml:"revision"`
}

func (p *GopkgTOMLParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GopkgTOMLParser file path: %s", path)
	lockPath := path[:len(path)-5] + ".lock"
	_, err := os.Stat(lockPath)
	if os.IsNotExist(err) {
		return parseGopkgLock(path)
	} else {
		return parseGopkgToml(path)
	}
}

func parseGopkgToml(path string) ([]model.Package, error) {
	file, err := toml.LoadFile(path)
	if err != nil {
		return nil, err
	}

	tomlFile := &gopkgToml{}
	err = file.Unmarshal(tomlFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	overrideDeps := make(map[string]struct{})
	for _, dep := range tomlFile.Overrides {
		pkg := newGopkgPackage(&dep, path)
		pkgs = append(pkgs, *pkg)
		overrideDeps[dep.Name] = struct{}{}
	}

	for _, dep := range tomlFile.Constraints {
		if _, found := overrideDeps[dep.Name]; found {
			continue
		}
		pkg := newGopkgPackage(&dep, path)
		pkgs = append(pkgs, *pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func parseGopkgLock(path string) ([]model.Package, error) {
	file, err := toml.LoadFile(path)
	if err != nil {
		return nil, err
	}

	lockFile := &gopkgLock{}
	err = file.Unmarshal(lockFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	overrideDeps := make(map[string]struct{})
	for _, dep := range lockFile.Project {
		pkg := newGopkgPackage(&dep, path)
		pkgs = append(pkgs, *pkg)
		overrideDeps[dep.Name] = struct{}{}
	}

	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func newGopkgPackage(dep *gopkgDep, sourcePath string) *model.Package {
	name := dep.Name
	version := dep.Version
	if strings.TrimSpace(version) == "" {
		version = dep.Revision
	}
	version = strings.TrimLeft(version, "^>=<")

	return newPackage(name, version, sourcePath)
}
