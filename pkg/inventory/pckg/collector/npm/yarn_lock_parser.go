// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package npm

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	empty = struct{}{}

	// match package name
	namePattern = regexp.MustCompile(`^"?((?:@\w[\w-_.]*\/)?\w[\w-_.]*)@`)

	// match package version
	versionPattern = regexp.MustCompile(`^\W+version(?:\W+"|:\W+)([\w-_.]+)"?`)

	// match resolved url to find name and version
	resolvedURLPattern = regexp.MustCompile(`^\s+resolved\s+"https://registry\.(?:yarnpkg\.com|npmjs\.org)/(.+?)/-/(?:.+?)-(\d+\..+?)\.tgz`)
)

// YarnLockParser is a parser for yarn.lock file
// see: https://classic.yarnpkg.com/lang/en/docs/yarn-lock/
type YarnLockParser struct{}

// format: name@version
type YarnPackageKey string
type YarnPackageContent struct {
	keys           []string
	name           string
	version        string
	pkg            *model.Package
	dependencyKeys []string
}

func NewYarnLockParser() *YarnLockParser {
	return &YarnLockParser{}
}

func (YarnLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"yarn.lock"}}
}

func (YarnLockParser) Parse(path string) ([]model.Package, error) {
	log.Infof("parse path %s", path)
	if hasSubFolder(path, folderNameNodeModules) {
		log.Warnf("yarn lock pash has %s retuen nil", folderNameNodeModules)
		return nil, nil
	}
	reader, err := os.Open(path)
	if err != nil {
		log.Errorf("yarn lock open %s error:%s", path, err.Error())
		return nil, err
	}

	defer func(reader *os.File) {
		_ = reader.Close()
	}(reader)
	var pkgs []model.Package
	scanner := bufio.NewScanner(reader)
	//pkgMap := make(map[string]struct{})
	//currentPkgDependencies := []string{}

	//depTree := collector.NewDependencyTree()

	//isNewPackageSnippet := false
	pkgContents := []YarnPackageContent{}
	var pkgContent YarnPackageContent
	//emptyContent := YarnPackageContent{}
	var dependenciesFlag bool
	var dependenciesItemContentPrefix = "    "
	var dependenciesText = "  dependencies:"
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if dependenciesFlag && line[:4] == dependenciesItemContentPrefix {
			pkgContent.dependencyKeys = append(pkgContent.dependencyKeys, toPackageKey(line))
		}
		if packageName := parseContentName(line); packageName != "" {
			//isNewPackageSnippet = true
			if pkgContent.name != "" {
				//store last package
				pkgContents = append(pkgContents, pkgContent)
			}
			pkgContent = YarnPackageContent{}
			pkgContent.name = packageName
			pkgContent.keys = toPackageKeys(line)
		} else if version := parseContentVersion(line); version != "" {
			pkgContent.version = version
		} else if packageName, version := parseContentResolved(line); packageName != "" && version != "" {
			pkgContent.name = packageName
			pkgContent.version = version
		} else if line == dependenciesText {
			dependenciesFlag = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse yarn.lock file error : %w", err)
	}

	// record package if not recorded yet
	if pkgContent.name != "" && pkgContent.version != "" {
		pkgContents = append(pkgContents, pkgContent)
	}

	pkgMap := make(map[string]*model.Package)
	for i := range pkgContents {
		pkgContents[i].pkg = newPackage(pkgContents[i].name, pkgContents[i].version, path)
		for _, key := range pkgContents[i].keys {
			pkgMap[key] = pkgContents[i].pkg
		}
	}

	depTree := collector.NewDependencyTree()
	for _, content := range pkgContents {
		depTree.AddPackage(content.pkg)
		for _, depKey := range content.dependencyKeys {
			depPkg := pkgMap[depKey]
			if depPkg != nil {
				depTree.AddDependency(content.pkg.PURL, depPkg.PURL)
			}
		}
	}

	pkgs = depTree.ToList()
	log.Infof("yarnLockParser %d packages found", len(pkgs))
	return pkgs, nil
}

func toPackageKeys(nameText string) []string {
	nameText = strings.TrimSuffix(nameText, ":")
	items := strings.Split(nameText, ",")
	normalizeKey(items)
	return items
}

func toPackageKey(dependencyText string) string {
	sep := " "
	if strings.Contains(dependencyText, ":") {
		sep = ":"
	}
	items := strings.Split(strings.TrimSpace(dependencyText), sep)
	normalizeKey(items)
	return strings.Join(items, "@")
}

func normalizeKey(items []string) {
	for i, item := range items {
		items[i] = strings.Trim(item, "\"")
		items[i] = strings.TrimSpace(items[i])
	}
}

func parseContentName(line string) string {
	if matches := namePattern.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func parseContentVersion(line string) string {
	if matches := versionPattern.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func parseContentResolved(line string) (string, string) {
	if matches := resolvedURLPattern.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1], matches[2]
	}
	return "", ""
}

func exist(items map[string]struct{}, key string) bool {
	_, ok := items[key]
	return ok
}
