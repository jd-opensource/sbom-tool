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
	"os"

	"gopkg.in/yaml.v3"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

// PubSpecYAMLParser is a parser for pubspec.yaml file
// see: https://dart.dev/tools/pub/pubspec
type PubSpecYAMLParser struct{}

// NewPubSpecYAMLParser returns a new PubSpecYAMLParser
func NewPubSpecYAMLParser() *PubSpecYAMLParser {
	return &PubSpecYAMLParser{}
}

func (p *PubSpecYAMLParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pubspec.yaml"}}
}

type pubSpecYaml struct {
	Name         string
	Version      string
	Dependencies map[string]interface{}
}

func (p *PubSpecYAMLParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := yaml.NewDecoder(file)

	yamlFile := &pubSpecYaml{}
	err = decoder.Decode(yamlFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	for name, obj := range yamlFile.Dependencies {
		var version string
		switch dep := obj.(type) {
		case string:
			version = dep
		case map[string]interface{}:
			if ver, ok1 := dep["version"]; ok1 {
				if v, ok2 := ver.(string); ok2 {
					version = v
				}
			}
		}
		pkg := newPackage(name, getVersion(version), path)
		pkgs = append(pkgs, pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
