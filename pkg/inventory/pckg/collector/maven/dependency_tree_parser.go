// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"bufio"
	"io"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// DependencyTreeParser is a parser for output of executing 'mvn dependency:tree' command.
// see: https://maven.apache.org/plugins/maven-dependency-plugin/tree-mojo.html
type DependencyTreeParser struct{}

var validMavenScopes = map[string]bool{
	"compile":  true,
	"provided": true,
	"runtime":  true,
	"test":     true,
	"system":   true,
	"import":   true,
}

// NewDependencyTreeParser returns a new DependencyTreeParser
func NewDependencyTreeParser() *DependencyTreeParser {
	return &DependencyTreeParser{}
}

func (m *DependencyTreeParser) Type() model.PkgType {
	return model.PkgTypeMaven
}

func (m *DependencyTreeParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"maven-dependency-tree.txt"}}
}

func (m *DependencyTreeParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMavenDependencyTreeFile(f, filePath)
}

func parseMavenDependencyTreeFile(reader io.Reader, sourcePath string) ([]model.Package, error) {
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
		lastBlankIdx := strings.LastIndex(pkgLine, " ")
		level := (lastBlankIdx + 1) / 3

		if level == 0 {
			rootPkg := generatePackage(pkgLine, lastBlankIdx, sourcePath)
			if rootPkg != nil {
				depTree.AddPackage(rootPkg)
			}
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
		lastBlankIdx := strings.LastIndex(line, " ")
		level := (lastBlankIdx + 1) / 3
		if level == parentLevel+1 {
			pkg := generatePackage(line, lastBlankIdx, sourcePath)
			if pkg != nil {
				depTree.AddPackage(pkg)
				if parentPkg != nil {
					depTree.AddDependency(parentPkg.PURL, pkg.PURL)
				}
			}
			scan := parseDependencies(pkg, depTree, pkgLines, i+1, level, sourcePath)
			scanLines = scanLines + scan + 1
			if line[lastBlankIdx-1:lastBlankIdx] == `\-` {
				return scanLines
			}
		} else if level <= parentLevel {
			return scanLines
		}
	}
	return scanLines
}

func generatePackage(line string, lastBlankIdx int, sourcePath string) *model.Package {
	splitPoint := 0
	if lastBlankIdx != -1 {
		splitPoint = lastBlankIdx
	}

	tags := strings.Split(line[splitPoint:], ":")

	if len(tags) < 3 {
		log.Errorf("parse dependency line error: %s\n", line)
		return nil
	}

	groupId := strings.TrimSpace(tags[0])
	artifactId := strings.TrimSpace(tags[1])
	version := ""

	isMavenScope := IsMavenScope(tags[len(tags)-1])
	if !isMavenScope {
		version = strings.TrimSpace(tags[len(tags)-1])
	} else {
		version = strings.TrimSpace(tags[len(tags)-2])
	}
	return newPackage(groupId, artifactId, version, sourcePath)
}

// IsMavenScope 判断字符串是否为Maven依赖坐标中scope的有效取值
func IsMavenScope(str string) bool {
	_, ok := validMavenScopes[str]
	return ok
}
