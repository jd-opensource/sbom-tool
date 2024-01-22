// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cargo

import (
	"github.com/anchore/packageurl-go"
	"github.com/microsoft/go-rustaudit"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

/*
*
* [[package]]
* name = "ansi_term"
* version = "0.12.1"
* source = "registry+https://github.com/rust-lang/crates.io-index"
* checksum = "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2"
* dependencies = [
* 	"winapi",
* ]
 */
type CargoPackageMetadata struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source" json:"source"`
	Checksum     string   `toml:"checksum" json:"checksum"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

func newPackage(name, version, filePath string) *model.Package {
	return &model.Package{
		Name:           name,
		Version:        version,
		Type:           PkgType(),
		PURL:           packageURL(name, version),
		SourceLocation: filePath,
	}
}

// packageURL returns the PURL for the specific rust package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		PkgType(),
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}

func NewPkgFromCargoMetadata(c CargoPackageMetadata, m map[string]CargoPackageMetadata, filePath string) model.Package {

	p := newPackage(c.Name, c.Version, filePath)

	if c.Dependencies == nil {
		p.Dependencies = []string{}
	} else {
		for _, d := range c.Dependencies {
			if pkg, exists := m[d]; exists {
				p.Dependencies = append(p.Dependencies, packageURL(pkg.Name, pkg.Version))
			}
		}
	}

	return *p
}

func NewPackageFromBinaryDependency(dependPackageList []rustaudit.Package, path string) []model.Package {
	pkgs := []model.Package{}
	for _, rustauditPkg := range dependPackageList {
		p := newPackage(rustauditPkg.Name, rustauditPkg.Version, path)
		pkgs = append(pkgs, *p)
	}
	//todo:rustauditPkg 中能够处理package的依赖关系，新的package结构调整完毕后在做
	return pkgs
}
