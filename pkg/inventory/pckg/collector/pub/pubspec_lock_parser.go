// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pub

import (
	"os"

	"gopkg.in/yaml.v3"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PubSpecLockParser is a parser for pubspec.lock file
// see: https://dart.dev/tools/pub/versioning#lockfiles
type PubSpecLockParser struct{}

// NewPubSpecLockParser returns a new PubSpecLockParser
func NewPubSpecLockParser() *PubSpecLockParser {
	return &PubSpecLockParser{}
}

func (p *PubSpecLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"pubspec.lock"}}
}

type pubSpecLock struct {
	Packages map[string]pubPkg
}

type pubPkg struct {
	Version    string
	Dependency string // dependency type: direct main transitive
}

func (p *PubSpecLockParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := yaml.NewDecoder(file)

	lockFile := &pubSpecLock{}
	err = decoder.Decode(lockFile)
	if err != nil {
		return nil, err
	}
	pkgs := make([]model.Package, 0)

	for name, pkg := range lockFile.Packages {
		pkg := newPackage(name, getVersion(pkg.Version), path)
		pkgs = append(pkgs, pkg)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
