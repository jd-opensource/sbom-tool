// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pypi

import (
	"bufio"
	"io"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// PipenvGraphParser is a parser for output of executing 'pipenv graph' command
// see: https://pypi.org/project/pipenv/#show-a-dependency-graph
type PipenvGraphParser struct{}

// NewPipenvGraphParser returns a new PipenvGraphParser
func NewPipenvGraphParser() *PipenvGraphParser {
	return &PipenvGraphParser{}
}

func (m *PipenvGraphParser) Type() model.PkgType {
	return model.PkgTypePyPi
}

func (m *PipenvGraphParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pipenv-graph", "pipenv-graph.txt"}}
}

func (m *PipenvGraphParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python PipenvGraphParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePipenvGraphFile(f, filePath)
}

func parsePipenvGraphFile(reader io.Reader, sourcePath string) ([]model.Package, error) {
	dependencyPkgArray := []string{}
	dependencyScanner := bufio.NewScanner(reader)

	for dependencyScanner.Scan() {
		line := dependencyScanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		dependencyPkgArray = append(dependencyPkgArray, line)
	}
	depTree := collector.NewDependencyTree()

	for i := 0; i < len(dependencyPkgArray); i++ {
		pkgLine := dependencyPkgArray[i]
		level := strings.Count(pkgLine, "  ")
		if level == 0 {
			rootPkg := generatePackage(pkgLine, level, sourcePath)
			depTree.AddPackage(rootPkg)
			scan := parseDependencies(rootPkg, depTree, dependencyPkgArray, i+1, level, sourcePath)
			i = i + scan
		}

	}
	pkgs := depTree.ToList()
	return pkgs, nil
}

func parseDependencies(parentPkg *model.Package, depTree *collector.DependencyTree, pkgLines []string, startLine int, parentLevel int, sourcePath string) int {
	scanLines := 0
	for i := startLine; i < len(pkgLines); i++ {
		line := pkgLines[i]
		level := strings.Count(line, "  ")
		if level == parentLevel+1 {
			pkg := generatePackage(line, level, sourcePath)
			depTree.AddPackage(pkg)
			depTree.AddDependency(parentPkg.PURL, pkg.PURL)
			scan := parseDependencies(pkg, depTree, pkgLines, i+1, level, sourcePath)
			scanLines = scanLines + scan + 1
		} else if level <= parentLevel {
			return scanLines
		}
	}
	return scanLines
}

func generatePackage(line string, level int, sourcePath string) *model.Package {
	line = strings.TrimSpace(line)
	var name string
	var version string
	if level == 0 {
		tags := strings.Split(line, "==")
		name = tags[0]
		version = tags[1]
	} else {
		tags := strings.Split(line, " ")
		name = tags[1]
		version = strings.ReplaceAll(tags[5], "]", "")
	}
	return newPackage(name, version, sourcePath)
}
