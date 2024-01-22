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
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var godeps_error_version_str1 = "xxxxxxxxxxxxxxxxx"

// GodepsJSONParser is a parser for Godeps.json file.
// see: https://github.com/tools/godep
type GodepsJSONParser struct{}

// NewGodepsJSONParser returns a new GodepsJSONParser
func NewGodepsJSONParser() *GodepsJSONParser {
	return &GodepsJSONParser{}
}

func (p *GodepsJSONParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Godeps.json"}}
}

// see https://github.com/tools/godep
type Godeps struct {
	ImportPath   string
	GoVersion    string   // Abridged output of 'go version'.
	GodepVersion string   // Abridged output of 'godep version'
	Packages     []string // Arguments to godep save, if any.
	Deps         []struct {
		ImportPath string
		Comment    string // Description of commit, if present.
		Rev        string // VCS-specific commit ID.
	}
}

func (p *GodepsJSONParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GodepsJSONParser file path: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := json.NewDecoder(file)

	jsonFile := &Godeps{}
	err = decoder.Decode(jsonFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	for _, dep := range jsonFile.Deps {
		name := dep.ImportPath
		version := dep.Rev
		if strings.Contains(version, godeps_error_version_str1) {
			version = ""
		}

		pkg := newPackage(name, version, path)
		pkgs = append(pkgs, *pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
