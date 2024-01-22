// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package deb

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"pault.ag/go/debian/dependency"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func newPackage(name, version string, path string) model.Package {
	if strings.Contains(version, "%") {
		version = ""
	}
	if strings.Contains(version, "$") {
		version = ""
	}

	version = strings.ReplaceAll(version, "~", "")

	return model.Package{
		Name:           name,
		Version:        version,
		Type:           PkgType(),
		PURL:           packageURL(name, version),
		SourceLocation: path,
	}
}

func packageURL(name, version string) string {
	pURL := packageurl.NewPackageURL(
		PkgType(),
		"debian",
		strings.TrimSpace(name),
		strings.TrimSpace(version),
		nil,
		"")
	return pURL.ToString()
}

func debDependPkgParser(depTree *collector.DependencyTree, parentPkg model.Package, binaryDepRel []dependency.Relation, path string) {
	for _, relation := range binaryDepRel {
		for _, possibility := range relation.Possibilities {
			if strings.Contains(possibility.Name, ":") {
				continue
			}
			var version string
			if possibility.Version == nil || possibility.Version.Number == "" {
				version = ""
			} else {
				version = possibility.Version.Number
			}
			pkg := newPackage(possibility.Name, version, path)
			depTree.AddPackage(&pkg)
			depTree.AddDependency(parentPkg.PURL, pkg.PURL)
		}
	}
}
