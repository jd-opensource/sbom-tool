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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/license"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// content of package.json
type packageJSONContent struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	License      json.RawMessage   `json:"license"`
	Licenses     json.RawMessage   `json:"licenses"`
	Dependencies map[string]string `json:"dependencies"`
}

type licenseField struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// PackageJSONParser is a parser for package.json file
// see: https://docs.npmjs.com/cli/v10/configuring-npm/package-json
type PackageJSONParser struct{}

func NewPackageJSONParser() *PackageJSONParser {
	return &PackageJSONParser{}
}

func (PackageJSONParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"package.json"}}
}

func (PackageJSONParser) ParseMain(path string) (pkg *model.Package, err error) {
	log.Infof("(main)parse path %s", path)
	content, err := getPackageJSONContent(path)
	if err != nil {
		return nil, err
	}
	pkg = newPackage(content.Name, content.Version, path)
	if pkg == nil {
		return nil, nil
	}
	// resolve license info
	licenses, _ := extractLicenses(content)
	pkg.LicenseDeclared = licenses
	return pkg, nil
}

func (PackageJSONParser) Parse(path string) ([]model.Package, error) {
	log.Infof("parse path %s", path)
	content, err := getPackageJSONContent(path)
	if err != nil {
		return nil, err
	}
	var pkgs []model.Package

	mainPkg := newPackage(content.Name, content.Version, path)
	if mainPkg == nil {
		return nil, nil
	}

	// resolve license info
	licenses, _ := extractLicenses(content)
	mainPkg.LicenseDeclared = licenses

	if !hasSubFolder(path, folderNameNodeModules) {
		// not in node_modules
		for name, version := range content.Dependencies {
			ver := strings.Trim(version, "^><=@~")
			pkg := newPackage(name, ver, path)
			pkgs = append(pkgs, *pkg)
			mainPkg.Dependencies = append(mainPkg.Dependencies, pkg.PURL)
		}
	}

	pkgs = append(pkgs, *mainPkg)
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func getPackageJSONContent(path string) (*packageJSONContent, error) {
	reader, _ := os.Open(path)
	defer func(reader *os.File) {
		_ = reader.Close()
	}(reader)
	if reader == nil {
		return nil, nil
	}
	dec := json.NewDecoder(reader)
	var content *packageJSONContent

	if err := dec.Decode(&content); err != nil {
		return nil, fmt.Errorf("failed to decode package.json file: %w", err)
	}
	return content, nil
}

func extractLicenses(content *packageJSONContent) ([]string, error) {
	licensesResult := make([]string, 0)
	if content == nil {
		return nil, nil
	}
	licenses, err := getFromLicenseField(content.License)
	if len(licenses) == 0 {
		licenses, err = getFromLicensesField(content.Licenses)
	}

	if len(licenses) == 0 {
		return nil, nil
	}

	for _, name := range licenses {
		value, _, _ := license.ParseLicenseName(name)
		if len(strings.TrimSpace(value)) != 0 {
			licensesResult = append(licensesResult, value)
		}
	}

	return licensesResult, err
}

// for details, ref https://docs.npmjs.com/cli/v9/configuring-npm/package-json#license
func getFromLicenseField(b []byte) ([]string, error) {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		return getFromLicenseString(str), nil
	}

	var obj licenseField
	err = json.Unmarshal(b, &obj)
	if err == nil {
		return []string{obj.Type}, nil
	}
	return nil, err
}

func getFromLicenseString(str string) []string {
	str = strings.TrimPrefix(str, "(")
	str = strings.TrimSuffix(str, ")")
	return strings.Split(str, " OR ")
}

func getFromLicensesField(b []byte) ([]string, error) {
	var objs []licenseField
	err := json.Unmarshal(b, &objs)
	if err != nil {
		return nil, errors.New("unmarshal failed")
	}

	licenses := make([]string, 0)
	for _, item := range objs {
		licenses = append(licenses, item.Type)
	}
	return licenses, nil
}
