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
	"fmt"
	"io"
	"os"

	"github.com/rogpeppe/go-internal/modfile"
	"github.com/rogpeppe/go-internal/module"
	"golang.org/x/exp/maps"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// GoModFileParser is a parser for go.mod file.
// see: https://go.dev/ref/mod#go-mod-file
type GoModFileParser struct{}

// NewGoModFileParser returns a new GoModFileParser
func NewGoModFileParser() *GoModFileParser {
	return &GoModFileParser{}
}

func (g GoModFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"go.mod"}}
}

func (g GoModFileParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GoModFileParser file path: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open go module: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read go module: %w", err)
	}

	modFile, err := modfile.Parse(path, contents, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	pkgMap := make(map[string]model.Package)
	for _, m := range modFile.Require {
		err := module.Check(m.Mod.Path, m.Mod.Version)
		if err != nil {
			log.Warnf("path or version invalid(%s@%s): %s ", m.Mod.Path, m.Mod.Version, err.Error())
			continue
		}
		p := newPackage(m.Mod.Path, m.Mod.Version, path)
		pkgMap[p.PURL] = *p
	}

	// replace old packages
	for _, m := range modFile.Replace {
		importPath, version := m.New.Path, m.New.Version
		err := module.Check(importPath, version)
		if err != nil {
			log.Warnf("path or version invalid(%s@%s): %s ", importPath, version, err.Error())
			importPath, version = m.Old.Path, m.Old.Version
			err := module.Check(importPath, version)
			if err != nil {
				log.Warnf("path or version invalid(%s@%s): %s ", importPath, version, err.Error())
				continue
			}
		}
		p := newPackage(importPath, version, path)
		pkgMap[p.PURL] = *p
	}

	// remove excluded packages
	for _, m := range modFile.Exclude {
		purl := packageURL(m.Mod.Path, m.Mod.Version)
		delete(pkgMap, purl)
	}

	pkgs := collector.OrganizePackage(maps.Values(pkgMap))
	return pkgs, nil
}
