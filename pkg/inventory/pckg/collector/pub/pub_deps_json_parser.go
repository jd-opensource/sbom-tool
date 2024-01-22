// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pub

import (
	"encoding/json"
	"os"
	"sort"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PubDepsJSONParser is a parser for output of executing 'pub deps' command
// see: https://dart.dev/tools/pub/versioning#lockfiles
type PubDepsJSONParser struct{}

// NewPubDepsJSONParser returns a new PubDepsJSONParser
func NewPubDepsJSONParser() *PubDepsJSONParser {
	return &PubDepsJSONParser{}
}

func (p *PubDepsJSONParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pub-deps.json"}}
}

type pubDepsJson struct {
	Root     string
	Packages []pubDepsPkg
}

type pubDepsPkg struct {
	Name         string
	Version      string
	Kind         string
	Dependencies []string // names of dependencies
	pkgModel     *model.Package
}

func (p *PubDepsJSONParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := json.NewDecoder(file)
	jsonFile := &pubDepsJson{}
	err = decoder.Decode(jsonFile)
	if err != nil {
		return nil, err
	}
	purlMap := make(map[string]string)
	for i := 0; i < len(jsonFile.Packages); i++ {
		if jsonFile.Packages[i].Kind != "dev" {
			name := jsonFile.Packages[i].Name
			version := jsonFile.Packages[i].Version
			pkg := newPackage(name, version, path)
			jsonFile.Packages[i].pkgModel = &pkg
			purlMap[name] = pkg.PURL
		}
	}
	pkgs := make([]model.Package, 0)
	// assembly package's dependencies
	for i := 0; i < len(jsonFile.Packages); i++ {
		pkg := jsonFile.Packages[i].pkgModel
		if jsonFile.Packages[i].Kind != "dev" && pkg != nil {
			deps := make([]string, 0)
			for _, depName := range jsonFile.Packages[i].Dependencies {
				if purl, found := purlMap[depName]; found && purl != "" {
					deps = append(deps, purl)
				}
			}
			sort.Strings(deps)
			pkg.Dependencies = deps
			pkgs = append(pkgs, *pkg)
		}
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
