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

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

// GradleLockParser is a parser for gradle.lockfile
// see: https://docs.gradle.org/current/userguide/dependency_locking.html
type GradleLockParser struct{}

// NewJavaGradleLockParser returns a new JavaGradleLockParser
func NewJavaGradleLockParser() *GradleLockParser {
	return &GradleLockParser{}
}

func (m *GradleLockParser) Type() model.PkgType {
	return model.PkgTypeMaven
}

func (m *GradleLockParser) Language() model.Language {
	return model.LanguageJava
}

func (m *GradleLockParser) Pattern() string {
	return "*gradle.lockfile*"
}

func (m *GradleLockParser) Parse(filePath string) ([]model.Package, []model.Relationship, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseGradleLock(f, filePath)
}

const depParts = 3

// parseGradleLock parses gradle.lockfile
func parseGradleLock(reader io.Reader, sourcePath string) ([]model.Package, []model.Relationship, error) {
	var pkgs []model.Package
	var rels []model.Relationship

	dependencyScanner := bufio.NewScanner(reader)

	for dependencyScanner.Scan() {
		line := strings.TrimSpace(dependencyScanner.Text())
		dependencyStr := strings.Trim(line, "\"")
		dependencyParts := strings.Split(dependencyStr, ":")

		if len(dependencyParts) == depParts {
			groupId := dependencyParts[0]
			artifactId := dependencyParts[1]
			version := strings.Split(dependencyParts[2], "=")[0]

			pkg := newPackage(groupId, artifactId, version, sourcePath)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
		}
	}
	return pkgs, rels, nil
}
