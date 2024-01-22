// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package collector

import (
	"sort"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

// DependencyTree maintains the package list and dependencies, and provides some useful methods
type DependencyTree struct {
	depMap map[string]struct{}
	pkgMap map[string]*model.Package
}

func NewDependencyTree() *DependencyTree {
	return &DependencyTree{
		depMap: make(map[string]struct{}),
		pkgMap: make(map[string]*model.Package),
	}
}

// AddPackage adds package to the list, check whether the package exists through PURL, if exists, the package properties will be combined
func (tree *DependencyTree) AddPackage(pkg *model.Package) {
	if foundPkg, found := tree.pkgMap[pkg.PURL]; found {
		newPkg := CombinePackage(foundPkg, pkg)
		tree.pkgMap[pkg.PURL] = newPkg
	} else {
		tree.pkgMap[pkg.PURL] = pkg
	}
}

// AddDependency adds a dependency, will add the dependency's PURL to the dependency list of the main package, and the main package must exist
func (tree *DependencyTree) AddDependency(mainPurl, depPurl string) {
	if mainPurl == "" || depPurl == "" || mainPurl == depPurl {
		return
	}
	mainPkg := tree.GetPackage(mainPurl)
	if mainPkg != nil {
		mainPkg.Dependencies = util.SliceUnique(append(mainPkg.Dependencies, depPurl))
		sort.Strings(mainPkg.Dependencies)
		tree.depMap[depPurl] = struct{}{}
	}
}

// GetPackage get a package via PURL
func (tree *DependencyTree) GetPackage(purl string) *model.Package {
	pkg, found := tree.pkgMap[purl]
	if found {
		return pkg
	}
	return nil
}

// GetRootPackages get root packages
func (tree *DependencyTree) GetRootPackages() []model.Package {
	pkgs := make([]model.Package, 0)
	for _, pkg := range tree.pkgMap {
		if _, found := tree.depMap[pkg.PURL]; !found {
			pkgs = append(pkgs, *pkg)
		}
	}
	return pkgs
}

// GetPackagesByName get packages via name
func (tree *DependencyTree) GetPackagesByName(name string) []model.Package {
	pkgs := make([]model.Package, 0)
	for _, pkg := range tree.pkgMap {
		if pkg.Name == name {
			pkgs = append(pkgs, *pkg)
		}
	}
	return pkgs
}

// GetDependencies get a package's dependency list via PURL
func (tree *DependencyTree) GetDependencies(purl string) []model.Package {
	pkg := tree.GetPackage(purl)
	if pkg != nil && len(pkg.Dependencies) > 0 {
		pkgs := make([]model.Package, 0)
		for _, dep := range pkg.Dependencies {
			p := tree.GetPackage(dep)
			if p != nil {
				pkgs = append(pkgs, *p)
			}
		}
		return pkgs
	}
	return nil
}

// IsExist Check if package exists via PURL
func (tree *DependencyTree) IsExist(purl string) bool {
	_, found := tree.pkgMap[purl]
	return found
}

// ToList returns a list of all packages
func (tree *DependencyTree) ToList() []model.Package {
	pkgs := make([]model.Package, len(tree.pkgMap))
	idx := 0
	for _, p := range tree.pkgMap {
		pkgs[idx] = *p
		idx++
	}
	return OrganizePackage(pkgs)
}
