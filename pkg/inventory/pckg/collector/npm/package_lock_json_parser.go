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
	"path/filepath"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// PackageLockJSONParser is a parser for package-lock.json file
// see: https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type PackageLockJSONParser struct{}

var folderNameNodeModules = "node_modules"

// content of package.json
type packageLockJSONContent struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Author          string          `json:"author"`
	License         json.RawMessage `json:"license"`
	Licenses        json.RawMessage `json:"licenses"`
	LockfileVersion int             `json:"lockfileVersion"`
	Dependencies    map[string]lockDependencyItem
	Packages        map[string]lockPackageItem
}

type lockPackageItem struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	License   string `json:"license"`
	Dev       bool   `json:"dev"`
}
type lockDependencyItem struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

func NewPackageLockJSONParser() *PackageLockJSONParser {
	return &PackageLockJSONParser{}
}

func (PackageLockJSONParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"package-lock.json"}}
}

func (PackageLockJSONParser) Parse(path string) ([]model.Package, error) {
	log.Infof("parse path %s", path)
	if hasSubFolder(path, folderNameNodeModules) {
		log.Warnf("package lock pash has %s retuen nil", folderNameNodeModules)
		return nil, nil
	}
	reader, err := os.Open(path)
	if err != nil {
		log.Errorf("package lock open %s error:%s", path, err.Error())
		return nil, err
	}
	defer func(reader *os.File) {
		_ = reader.Close()
	}(reader)
	dec := json.NewDecoder(reader)
	var content packageLockJSONContent

	if err := dec.Decode(&content); err != nil {
		log.Errorf("package lock Decode %s error:%s", path, err.Error())
		return nil, fmt.Errorf("failed to decode package.json file: %w", err)
	}
	var pkgs []model.Package
	dir := filepath.Dir(path)
	nodeModulesExist, _ := util.PathExists(filepath.Join(dir, folderNameNodeModules))
	log.Infof("package lock path nodeModulesExist is : %t", nodeModulesExist)
	// the lockfileVersion differs depending on the npm version. for details ref https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json#lockfileversion
	if content.LockfileVersion == 1 {
		for name, dep := range content.Dependencies {
			if dep.Dev {
				continue
			}
			pkg := newPackage(name, dep.Version, path)
			if nodeModulesExist {
				subPkgPath := filepath.Join(dir, folderNameNodeModules, name, "package.json")
				licenses, err := selectLicenses(subPkgPath)
				if err != nil {
					log.Errorf("select licenses error: %s", err.Error())
				}
				pkg.LicenseConcluded = licenses
			}
			pkgs = append(pkgs, *pkg)
		}
		if pkgs != nil && len(pkgs) > 0 {
			log.Infof("package lock LockfileVersion 1 pkgs len is : %d", len(pkgs))
		}
	} else if content.LockfileVersion == 2 || content.LockfileVersion == 3 {
		for name, item := range content.Packages {
			if item.Dev {
				continue
			}
			if name == "" && item.Name == "" {
				continue
			}
			depName := name
			if depName == "" {
				depName = item.Name
			}

			modIndex := strings.LastIndex(depName, "node_modules/")
			if modIndex > -1 {
				depName = depName[modIndex+13:]
			}

			pkg := newPackage(depName, item.Version, path)
			var licenses []string
			if item.License != "" {
				licenses = getFromLicenseString(item.License)
				pkg.LicenseDeclared = licenses
			}
			if len(licenses) == 0 && nodeModulesExist {
				subPkgPath := filepath.Join(dir, name, "package.json")
				licenses, err := selectLicenses(subPkgPath)
				if err != nil {
					log.Warnf("select licenses error: %s", err.Error())
				}
				pkg.LicenseConcluded = licenses
			}
			pkgs = append(pkgs, *pkg)
		}
		if pkgs != nil && len(pkgs) > 0 {
			log.Infof("package lock LockfileVersion 2	or 3 pkgs len is : %d", len(pkgs))
		}
	}
	pkgs = collector.SortPackage(pkgs)
	log.Infof("%d packages found", len(pkgs))
	return pkgs, nil
}

func selectLicenses(packageJSONPath string) ([]string, error) {
	stat, err := os.Stat(packageJSONPath)
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, errors.New("not file")
	}
	subPkgContent, err := getPackageJSONContent(packageJSONPath)
	if err != nil {
		return nil, err
	}
	licenses, err := extractLicenses(subPkgContent)
	if err != nil {
		return nil, err
	}
	return licenses, nil
}

var separator = regexp.MustCompile(`[\\/]`)

func hasSubFolder(path, folderName string) bool {
	items := separator.Split(path, -1)
	return util.SliceContains(items, folderName)
}
