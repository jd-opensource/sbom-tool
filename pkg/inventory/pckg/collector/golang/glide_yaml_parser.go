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

	"gopkg.in/yaml.v3"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// GlideYAMLParser is a parser for glide.yaml file.
// see: https://github.com/Masterminds/glide
type GlideYAMLParser struct{}

// NewGlideYAMLParser returns a new GlideYAMLParser
func NewGlideYAMLParser() *GlideYAMLParser {
	return &GlideYAMLParser{}
}

func (p *GlideYAMLParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"glide.yml", "glide.yaml"}}
}

// see https://github.com/Masterminds/glide/blob/master/cfg/cfg.go
type glideYaml struct {
	Package  string
	Homepage string
	License  string
	Import   []struct {
		Package string
		Version string
	}
}

func (p *GlideYAMLParser) Parse(path string) ([]model.Package, error) {
	log.Infof("golang GlideYAMLParser file path: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := yaml.NewDecoder(file)

	yamlFile := &glideYaml{}
	err = decoder.Decode(yamlFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	for _, glidePkg := range yamlFile.Import {
		name := glidePkg.Package
		version := strings.TrimLeft(glidePkg.Version, "^>=<~")

		pkg := newPackage(name, version, path)
		pkgs = append(pkgs, *pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
