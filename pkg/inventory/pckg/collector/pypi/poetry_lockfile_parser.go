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
	"io"
	"os"
	"strings"

	"github.com/pelletier/go-toml"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var pkgVersionMap = make(map[string]string)

type PoetryLockData struct {
	PoetryPackages []struct {
		Name         string                 `toml:"name"`
		Version      string                 `toml:"version"`
		Dependencies map[string]interface{} `toml:"dependencies"`
	} `toml:"package"`
}

// PoetryLockParser is a parser for poetry.lock file
// see: https://python-poetry.org/docs/basic-usage/#installing-dependencies
type PoetryLockParser struct{}

func NewPoetryLockParser() *PoetryLockParser {
	return &PoetryLockParser{}
}

func (m *PoetryLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"poetry.lock"}}
}

func (m *PoetryLockParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python PoetryLockParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parsePoetryLockFile(f, filePath)
}

func parsePoetryLockFile(reader io.Reader, sourcePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	poetryLockTree, err := toml.LoadReader(reader)
	if err != nil {
		log.Errorf("load  poetry.lock error: %s", err.Error())
	}
	poetryLockData := PoetryLockData{}
	err = poetryLockTree.Unmarshal(&poetryLockData)
	if err != nil {
		log.Errorf("parse poetry.lock error: %s", err.Error())
	}

	for _, poetryPackage := range poetryLockData.PoetryPackages {
		if _, ok := pkgVersionMap[poetryPackage.Name]; !ok {
			pkgVersionMap[poetryPackage.Name] = poetryPackage.Version
		}
	}

	for _, poetryPackage := range poetryLockData.PoetryPackages {
		packageName := strings.TrimSpace(poetryPackage.Name)
		packageVersion := strings.TrimSpace(poetryPackage.Version)
		if packageName == "" {
			continue
		}
		pkg := newPackage(packageName, packageVersion, sourcePath)

		if poetryPackage.Dependencies != nil {
			pkg.Dependencies = parseDependenciesList(poetryPackage.Dependencies)
		}

		pkgs = append(pkgs, *pkg)
	}

	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func parseDependenciesList(dependenciesList map[string]interface{}) []string {
	depList := make([]string, 0)
	for name := range dependenciesList {
		pkgUrl := packageURL(name, pkgVersionMap[name])
		depList = append(depList, pkgUrl)
	}
	return depList
}
