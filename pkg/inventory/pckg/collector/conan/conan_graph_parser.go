// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conan

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

type Node struct {
	Name         string                `json:"name"`
	Version      string                `json:"version"`
	License      string                `json:"license"`
	Dependencies map[string]Dependency `json:"dependencies"`
}

type Dependency struct {
	Ref string `json:"ref"`
}

type Graph struct {
	Nodes map[string]Node `json:"nodes"`
}

type ParserFile struct {
	Graph Graph `json:"graph"`
}

// ConanGraphParser is a parser for output of executing 'conan graph info' command
// see: https://docs.conan.io/2/reference/commands/graph/info.html
type ConanGraphParser struct{}

func NewConanGraphParser() *ConanGraphParser {
	return &ConanGraphParser{}
}

func (m *ConanGraphParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"conan-graph-info.json"}}
}

func (m *ConanGraphParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseConanGraphJsonFile(f, filePath)
}

func parseConanGraphJsonFile(reader io.Reader, path string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	// 解析JSON数据
	var graphFile ParserFile

	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&graphFile)
	if err != nil {
		log.Errorf("Failed to decode parseConanGraphJsonFile: %s", err.Error())
		return pkgs, err
	}
	var graph = graphFile.Graph
	// 解析节点信息
	for _, node := range graph.Nodes {
		// 如果节点对name为null就跳过处理
		if IsEmptyOrNull(node.Name) || IsEmptyOrNull(node.Version) {
			continue
		}
		//创建依赖包对象
		pkg := newPackage(node.Name, node.Version, path)
		//如果license不为空，赋值
		if IsEmptyOrNull(node.License) {
			pkg.LicenseConcluded = []string{node.License}
		}

		// 如果依赖对象不为空，解析依赖
		if node.Dependencies != nil {
			for _, dep := range node.Dependencies {
				//如果依赖对ref字段不为空
				if !IsEmptyOrNull(dep.Ref) {
					//截取name和version
					split := strings.Split(dep.Ref, "/")
					if len(split) == 2 && !IsEmptyOrNull(split[0]) && !IsEmptyOrNull(split[1]) {
						depPkg := newPackage(node.Name, node.Version, path)
						purl := depPkg.PURL
						pkg.Dependencies = append(pkg.Dependencies, purl)
					}
				}
			}
		}
		pkgs = append(pkgs, *pkg)
	}
	return pkgs, nil
}

func IsEmptyOrNull(str string) bool {
	return str == "" || str == "null" || str == "NULL"
}
