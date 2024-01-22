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
	"github.com/vifraa/gopom"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

var badStrs = []string{"$", " ", "%", "@", "<", "[", "]", "(", ")", "/"}

// POMXMLParser is a parser for maven pom.xml
// see: https://maven.apache.org/guides/introduction/introduction-to-the-pom.html
type POMXMLParser struct{}

// NewPOMXMLParser returns a new MavenPOMParser
func NewPOMXMLParser() *POMXMLParser {
	return &POMXMLParser{}
}

func (m *POMXMLParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pom.xml"}}
}

func (m *POMXMLParser) Parse(pomPath string) ([]model.Package, error) {
	return parsePomFile(pomPath)
}

// parsePomFile parses pom.xml
func parsePomFile(path string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	pomInfo, err := gopom.Parse(path)
	if err != nil {
		return nil, err
	}

	for _, dependencyPkg := range pomInfo.Dependencies {
		groupId := trim(dependencyPkg.GroupID)
		artifactId := trim(dependencyPkg.ArtifactID)
		version := trim(dependencyPkg.Version)
		pkg := newPackage(groupId, artifactId, version, path)
		if pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
	}

	return pkgs, nil
}
