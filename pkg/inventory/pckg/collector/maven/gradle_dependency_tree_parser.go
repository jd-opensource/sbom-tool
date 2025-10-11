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
	"os"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// Divide the content within the 'gradle dependencies' into distinct segments.
// eg: segment.name=runtimeClasspath,segment.lines=[dependencies details...]
type segment struct {
	headline string
	lines    []string
}

// GradleDependencyTreeParser is a parser for output of executing 'gradlew dependencies' command.
// see: https://docs.gradle.org/current/userguide/command_line_interface.html#listing_project_dependencies
type GradleDependencyTreeParser struct{}

// NewGradleDependencyTreeParser returns a new GradleDependencyTreeParser
func NewGradleDependencyTreeParser() *GradleDependencyTreeParser {
	return &GradleDependencyTreeParser{}
}

func (m *GradleDependencyTreeParser) Type() model.PkgType {
	return model.PkgTypeMaven
}

func (m *GradleDependencyTreeParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"gradle-dependency-tree.txt"}}
}

func (m *GradleDependencyTreeParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lines := []string{}
	textScanner := bufio.NewScanner(f)

	for textScanner.Scan() {
		line := textScanner.Text()
		line = strings.Trim(line, "\r")
		lines = append(lines, line)
	}

	return parseGradleDependencyTreeFile(lines, filePath)
}

func parseGradleDependencyTreeFile(lines []string, sourcePath string) ([]model.Package, error) {
	pkgMap := make(map[string]*model.Package)

	itemLines, mainPackage := getItemLinesAndMainPkg(pkgMap, lines, sourcePath)
	parseDependenciesLines(mainPackage, pkgMap, itemLines, 0, 0, sourcePath)

	if mainPackage != nil {
		for purl, pkgs := range pkgMap {
			if strings.Contains(purl, "preparatory_dependency") {
				mainPackage.Dependencies = append(mainPackage.Dependencies, pkgs.Dependencies...)
			}
		}
	}

	delete(pkgMap, "pkg:maven/preparatory_dependency")
	pkgs := make([]model.Package, 0)
	for _, p := range pkgMap {
		pkgs = append(pkgs, *p)
	}
	return collector.SortPackage(pkgs), nil
}

func parseDependenciesLines(parentPkg *model.Package, pkgMap map[string]*model.Package, pkgLines []string, startLine int, parentLevel int, sourcePath string) int {
	scanLines := 0
	for i := startLine; i < len(pkgLines); i++ {
		line := pkgLines[i]
		lastBlankIdx := findDashIndex(line)
		level := (lastBlankIdx + 1) / 5
		if level == parentLevel+1 {
			pkg := parsePackageFromLine(line, sourcePath)
			if pkg != nil {
				if _, found := pkgMap[pkg.PURL]; !found {
					pkgMap[pkg.PURL] = pkg
				}
				if parentPkg != nil && !slices.Contains(parentPkg.Dependencies, pkg.PURL) && !strings.Contains(pkg.Name, "preparatory_dependency") {
					parentPkg.Dependencies = append(parentPkg.Dependencies, pkg.PURL)
				}
			}
			scan := parseDependenciesLines(pkg, pkgMap, pkgLines, i+1, level, sourcePath)
			scanLines = scanLines + scan + 1
			if line[lastBlankIdx-4:lastBlankIdx] == `\---` {
				return scanLines
			}
		} else if level <= parentLevel {
			return scanLines
		}
	}
	return scanLines
}

var __parseDepElementPattern1 = regexp.MustCompile(`^([A-Za-z0-9\.-]+)\:([A-Za-z0-9\.-]+)(?:\:([A-Za-z0-9\.-]+))?(?: *-> *([A-Za-z0-9\.-]+))?`)
var __parseDepElementPattern2 = regexp.MustCompile(`^project\s*:?\s*([A-Za-z0-9_.:-]+)?`)

func parsePackageFromLine(s string, sourcePath string) *model.Package {
	s = strings.TrimLeft(s, "+- |\\/")
	if m := __parseDepElementPattern1.FindStringSubmatch(s); m != nil {

		groupId := strings.TrimSpace(m[1])
		artifactId := strings.TrimSpace(m[2])
		version := strings.TrimSpace(m[3])

		strictlyVersion, exist := strictlyVersionParse(s)
		if exist && version == "" {
			version = strings.Split(strictlyVersion, " ")[1]
		}

		if m[4] != "" && version == "" {
			version = m[4]
		}

		return newPackage(groupId, artifactId, version, sourcePath)
	}

	if m := __parseDepElementPattern2.FindStringSubmatch(s); m != nil {
		return newPackage("", m[1], "", sourcePath)
	}
	return nil
}

// com.diffplug.spotless:spotless-plugin-gradle:{strictly 6.6.0} -> 6.6.0 (c) ----> 6.6.0
func strictlyVersionParse(input string) (string, bool) {
	pattern := regexp.MustCompile(`\{([^}]+)\}`)
	match := pattern.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1], true
	}
	return "", false
}

func findDashIndex(input string) int {
	dashCount := 0
	for index, char := range input {
		if char == '-' {
			dashCount++
			if dashCount == 3 {
				return index + 1
			}
		} else {
			dashCount = 0
		}
	}
	return -1
}

func getItemLinesAndMainPkg(pkgMap map[string]*model.Package, lines []string, sourcePath string) ([]string, *model.Package) {
	itemLines := []string{}
	taskPattern := regexp.MustCompile(`^\w+$|^\w+\s-`)
	projectPattern := regexp.MustCompile("(?:Root project|[Pp]roject) ([':A-Za-z0-9._-]+)")

	mainPackage := &model.Package{}

	var segments []segment
	var currTaskName string
	var currTaskLines []string
	for _, it := range lines {
		if m := projectPattern.FindStringSubmatch(it); len(m) > 0 && mainPackage.Name == "" {
			mainPackage = newPackage("", strings.TrimSpace(strings.Trim(m[1], "'")), "", sourcePath)
			continue
		}
		if it == "" {
			if currTaskName != "" {
				segments = append(segments, segment{currTaskName, currTaskLines})
				currTaskLines = nil
				currTaskName = ""
			}
			continue
		}
		if m := taskPattern.FindString(it); m != "" {
			if currTaskName != "" {
				segments = append(segments, segment{currTaskName, currTaskLines})
				currTaskLines = nil
			}
			currTaskName = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(m), "-"))
			continue
		}
		if currTaskName == "" {
			continue
		}
		if strings.TrimSpace(it) == "|--- project : (*)" {
			continue
		}

		if containsOnlyProject(it) {
			it = it + "preparatory_dependency"
		}

		currTaskLines = append(currTaskLines, it)
	}

	if _, found := pkgMap[mainPackage.Name]; !found {
		pkgMap[mainPackage.Name] = mainPackage
	}

	for _, segment := range segments {
		// Look for "untimeClasspath" since it could be "RuntimeClasspath" or "runtimeClasspath"
		if strings.Contains(segment.headline, "untimeClasspath") {
			itemLines = segment.lines
		}
	}

	return itemLines, mainPackage
}

func containsOnlyProject(input string) bool {
	pattern := regexp.MustCompile(`^[^\w]*(project)[^\w]*$`)
	return pattern.MatchString(input)
}
