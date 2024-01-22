// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package nuget

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yalp/jsonpath"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

type NuGetJsonFileParser struct {
}

// NewNuGetJsonFileParser returns a new NuGetJsonFileParser
func NewNuGetJsonFileParser() *NuGetJsonFileParser {
	return &NuGetJsonFileParser{}
}

func (g NuGetJsonFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.nuget.dgspec.json"}}
}

func (g NuGetJsonFileParser) Parse(path string) ([]model.Package, error) {
	var pkgs []model.Package
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()
	bytes, _ := io.ReadAll(file)
	var json_data interface{}
	err = json.Unmarshal(bytes, &json_data)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	depObj, _ := jsonpath.Read(json_data, "$..dependencies")
	deps := depObj.([]interface{})

	for _, dep := range deps {
		if depMap, ok1 := dep.(map[string]interface{}); ok1 {
			for depKey, depValue := range depMap {
				if depInfo, ok2 := depValue.(map[string]interface{}); ok2 {
					autoReferenced := depInfo["autoReferenced"]
					if autoReferenced != nil && autoReferenced.(bool) == true {
						continue
					}
					version := depInfo["version"].(string)
					version = version[1:strings.Index(version, ",")]

					pkg := newPackage(depKey, version, path)
					pkgs = append(pkgs, *pkg)
				}
			}
		}
	}
	// sort packages
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
