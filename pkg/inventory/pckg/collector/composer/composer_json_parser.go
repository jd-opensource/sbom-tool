// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package composer

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	regComposerVersion = regexp.MustCompile(`(\d+\.\d+\.\d+|\d+\.\d+)`)
)

type ComposerInfo struct {
	Name      string            `json:"name"`
	License   string            `json:"license"`
	DepPkgMap map[string]string `json:"require"`
}

// ComposerJsonFileParser is a parser for composer.json file
// see: https://getcomposer.org/doc/04-schema.md
type ComposerJsonFileParser struct{}

func NewComposerJsonFileParser() *ComposerJsonFileParser {
	return &ComposerJsonFileParser{}
}

func (m *ComposerJsonFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"composer.json"}}
}

func (m *ComposerJsonFileParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseComposerJsonFile(f, filePath)
}

func parseComposerJsonFile(reader io.Reader, filePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	var composerInfo ComposerInfo
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&composerInfo)
	if err != nil {
		log.Errorf("Failed to decode parseComposerJsonFile: %s", err.Error())
		return pkgs, err
	}

	for pkgName, pkgVersion := range composerInfo.DepPkgMap {
		pkgName = strings.TrimSpace(pkgName)
		pkgVersion = strings.TrimSpace(pkgVersion)

		if strings.ToLower(pkgName) == "php" {
			continue
		}

		if strings.Contains(pkgVersion, "*") || !strings.Contains(pkgVersion, ".") {
			continue
		}

		pkgVersion = composerVersionParser(pkgVersion)

		if pkgName == "" {
			continue
		}

		pkg := newPackage(pkgName, pkgVersion, filePath)
		pkgs = append(pkgs, *pkg)

	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func composerVersionParser(versionStr string) string {
	var version string
	if strings.Contains(versionStr, "|") && !strings.Contains(versionStr, "||") {
		versionList := strings.Split(versionStr, "｜")
		version = circularVersionMatch(versionList)
	} else if strings.Contains(versionStr, "||") {
		versionList := strings.Split(versionStr, "||")
		version = circularVersionMatch(versionList)
	} else {
		version = regComposerVersion.FindString(versionStr)
	}

	return version
}

func circularVersionMatch(versionList []string) string {
	var version = ""
	for _, value := range versionList {
		value = strings.TrimSpace(value)
		if regComposerVersion.MatchString(value) {
			version = regComposerVersion.FindString(value)
			break
		}
	}

	return version
}
