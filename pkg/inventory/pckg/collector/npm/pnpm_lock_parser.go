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
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

type LockFile struct {
	LockfileVersion string                 `yaml:"lockfileVersion"`
	Dependencies    map[string]any         `yaml:"dependencies,omitempty"`
	DevDependencies map[string]any         `yaml:"devDependencies,omitempty"`
	Packages        map[string]PackageInfo `yaml:"packages,omitempty"`
}

type PackageInfo struct {
	Resolution      PackageResolution `yaml:"resolution"`
	Dependencies    map[string]string `yaml:"dependencies,omitempty"`
	DevDependencies map[string]string `yaml:"devDependencies,omitempty"`
	IsDev           bool              `yaml:"dev,omitempty"`
	Name            string            `yaml:"name,omitempty"`
	Version         string            `yaml:"version,omitempty"`
}

type PackageResolution struct {
	Tarball string `yaml:"tarball,omitempty"`
}

type PnpmLockParser struct{}

// NewPnpmLockParser returns a new PnpmLockParser
func NewPnpmLockParser() *PnpmLockParser {
	return &PnpmLockParser{}
}

func (PnpmLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pnpm.lock", "pnpm-lock.yaml"}}
}

func (PnpmLockParser) Parse(path string) ([]model.Package, error) {
	log.Infof("parse path %s", path)
	if hasSubFolder(path, folderNameNodeModules) {
		log.Errorf("pnpm lock pash has %s retuen nil", folderNameNodeModules)
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		log.Errorf("pnpm lock open %s error:%s", path, err.Error())
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	var lockFile LockFile
	if err := yaml.NewDecoder(file).Decode(&lockFile); err != nil {
		log.Errorf("pnpm lock Decode error:%s", err.Error())
		return nil, err
	}
	lockVersion, err := strconv.ParseFloat(lockFile.LockfileVersion, 64)
	if err != nil {
		log.Errorf("pnpm lock get lockVersion error:%s", err.Error())
	}
	log.Infof("pnpm lock lockVersion is :%f", lockVersion)
	separator := getVersionSeparator(lockVersion)
	log.Infof("pnpm lock separator is :%s", separator)
	depTree := collector.NewDependencyTree()

	if lockFile.Packages != nil && len(lockFile.Packages) > 0 {
		log.Infof("pnpm lock  lockFile.Packages len is : %d", len(lockFile.Packages))
	}

	// for pnpm.lock spec, ref https://github.com/pnpm/spec/blob/ad27a225f81d9215becadfa540ef05fa4ad6dd60/lockfile/5.md
	for key, value := range lockFile.Packages {
		if value.IsDev {
			continue
		}
		name := value.Name
		version := value.Version

		if name == "" {
			name, version = extractNameVersion(key, separator)
		}

		pkg := newPackage(name, version, path)
		depTree.AddPackage(pkg)
		for depName, depVer := range value.Dependencies {
			depTree.AddDependency(pkg.PURL, newPackage(depName, depVer, path).PURL)
		}
	}
	pkgs := depTree.ToList()
	log.Infof("pnpmLockParser %d packages found", len(pkgs))
	return pkgs, nil
}

func getVersionSeparator(lockFileVersion float64) string {
	sep := "@"
	if lockFileVersion < 6 {
		sep = "/"
	}
	return sep
}

func extractNameVersion(depPath, separator string) (string, string) {
	_, depPath, _ = strings.Cut(depPath, "/")
	var scope string
	if strings.HasPrefix(depPath, "@") {
		scope, depPath, _ = strings.Cut(depPath, "/")
	}
	var name, version string
	name, version, _ = strings.Cut(depPath, separator)
	if scope != "" {
		name = fmt.Sprintf("%s/%s", scope, name)
	}
	// Trim part with '_' or '(' char
	if idx := strings.IndexAny(version, "_("); idx != -1 {
		version = version[:idx]
	}
	return name, version
}
