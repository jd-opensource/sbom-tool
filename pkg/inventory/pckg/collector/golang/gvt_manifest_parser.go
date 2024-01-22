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
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// GvtManifestParser is a parser for vendor/manifest file of gvt.
// see: https://github.com/FiloSottile/gvt
type GvtManifestParser struct{}

// NewGvtManifestParser returns a new GodepsJSONParser
func NewGvtManifestParser() *GvtManifestParser {
	return &GvtManifestParser{}
}

func (p *GvtManifestParser) Matcher() collector.FileMatcher {
	return &collector.FileRegexpMatcher{Regexps: []*regexp.Regexp{regexp.MustCompile(`^.*/vendor/manifest$`)}}
}

// see https://github.com/FiloSottile/gvt
type GvtJson struct {
	Dependencies []struct {
		ImportPath string
		Revision   string
		Path       string
	}
}

func (p *GvtManifestParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GvtManifestParser file path: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := json.NewDecoder(file)

	jsonFile := &GvtJson{}
	err = decoder.Decode(jsonFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)
	for _, dep := range jsonFile.Dependencies {
		name := dep.ImportPath
		if dep.Path != "" && strings.HasSuffix(name, dep.Path) {
			name = name[:len(name)-len(dep.Path)]
			name = strings.TrimRight(name, "/")
		}
		version := dep.Revision
		pkg := newPackage(name, version, path)
		pkgs = append(pkgs, *pkg)
	}
	pkgs = collector.OrganizePackage(pkgs)
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
