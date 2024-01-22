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

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

var trimStringArr = []string{"\"", "'", "(", ")"}

type Plugin struct {
	GroupID string
	Version string
}

// GradleFileParser is a parser for build.gradle
// see: https://docs.gradle.org/current/userguide/working_with_files.html
type GradleFileParser struct{}

// NewJavaGradleFileParser returns a new GradleFileParser
func NewJavaGradleFileParser() *GradleFileParser {
	return &GradleFileParser{}
}

func (m *GradleFileParser) Type() model.PkgType {
	return model.PkgTypeMaven
}

func (m *GradleFileParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*build.gradle*"}}
}

func (m *GradleFileParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseGradleFile(f, filePath)
}

// parseGradleFile parses build.gradle
func parseGradleFile(reader io.Reader, sourcePath string) ([]model.Package, error) {
	var pkgs []model.Package
	var plugins []Plugin
	dependencyScanner := bufio.NewScanner(reader)
	dependenciesSign := false
	dependencyEndFlagNum := 0
	pluginsSign := false

	for dependencyScanner.Scan() {
		line := dependencyScanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "exclude") {
			continue
		}

		if strings.HasPrefix(line, "dependencies {") {
			dependenciesSign = true

			continue
		}

		if strings.HasPrefix(line, "plugins {") {
			pluginsSign = true

			continue
		}

		if line == "}" {
			if dependencyEndFlagNum > 0 {
				dependencyEndFlagNum = dependencyEndFlagNum - 1
				continue
			}
			if dependencyEndFlagNum == 0 {
				dependenciesSign = false
			}

			pluginsSign = false
			continue
		}

		if pluginsSign {
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.Contains(line, "version") {
				start := strings.Index(fields[0], "(") + 1
				end := strings.Index(fields[0], ")")
				if start < 1 || end < 0 || start >= end {
					continue
				}
				groupName := trimCustomString(fields[0][start:end], trimStringArr)
				version := trimCustomString(fields[2], trimStringArr)
				plugin := Plugin{GroupID: groupName, Version: version}
				plugins = append(plugins, plugin)
			}
		}

		if dependenciesSign {
			if strings.Contains(line, "{") {
				dependencyEndFlagNum = dependencyEndFlagNum + 1
			}

			if strings.Contains(line, "classpath") || strings.Contains(line, "project(") || strings.Contains(line, "fileTree(") {
				continue
			}

			start := strings.IndexFunc(line, func(r rune) bool {
				return r == '(' || r == ' '
			}) + 1

			end := len(line) - 1
			dependencyStr := trimCustomString(line[start:end], trimStringArr)
			dependencyParts := strings.Split(dependencyStr, ":")

			if len(dependencyParts) == 2 {
				artifactId := dependencyParts[1]
				version, groupId := getVersionAndGroupIDFromPlugins(dependencyParts[0], plugins)
				pkg := newPackage(groupId, artifactId, version, sourcePath)
				if pkg != nil {
					pkgs = append(pkgs, *pkg)
				}
			}
			if len(dependencyParts) == 3 || len(dependencyParts) == 4 {
				artifactId := dependencyParts[1]
				groupId := dependencyParts[0]
				version := dependencyParts[2]
				if strings.Contains(version, "$") || strings.Contains(version, "+") {
					version = ""
				}
				pkg := newPackage(groupId, artifactId, version, sourcePath)
				if pkg != nil {
					pkgs = append(pkgs, *pkg)
				}
			}
		}
	}

	return pkgs, nil
}

func getVersionAndGroupIDFromPlugins(group string, plugins []Plugin) (string, string) {
	for _, v := range plugins {
		if v.GroupID == group {
			return v.Version, v.GroupID
		}
	}
	return "", ""
}

func trimCustomString(line string, stringArr []string) string {
	for _, str := range stringArr {
		line = strings.ReplaceAll(line, str, "")
	}
	return strings.Trim(line, " ")
}
