// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package bower

import (
	"encoding/json"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// BowerJSONParser is a parser for bower.json file.
// see: https://github.com/bower/spec/blob/master/json.md
type BowerJSONParser struct{}

// NewBowerJSONParser returns a new CartFileParser
func NewBowerJSONParser() *BowerJSONParser {
	return &BowerJSONParser{}
}

func (p *BowerJSONParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"bower.json"}}
}

type bowerJson struct {
	Name         string            `json:"name"`
	License      string            `json:"license"`
	Dependencies map[string]string `json:"dependencies"`
}

func (p *BowerJSONParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(file)
	pkgs := make([]model.Package, 0)
	jsonFile := &bowerJson{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&jsonFile)
	if err != nil {
		log.Errorf("Failed to decode parseConanGraphJsonFile: %s", err.Error())
		return pkgs, err
	}
	for name, version := range jsonFile.Dependencies {
		ver := strings.TrimLeft(version, "^~>==< ")
		pkg := newPackage(name, ver, path)
		pkgs = append(pkgs, pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
