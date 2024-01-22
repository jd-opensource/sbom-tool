// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"strings"

	"github.com/anchore/packageurl-go"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func newPackage(groupId, artifactId, version string, path string) *model.Package {
	groupId, artifactId, version = normalize(groupId, artifactId, version)
	if artifactId == "" {
		return nil
	}
	name := artifactId
	if groupId != "" {
		name = groupId + "/" + artifactId
	}
	return &model.Package{
		Name:           name,
		Version:        version,
		Type:           PkgType(),
		PURL:           packageURL(artifactId, version, groupId),
		SourceLocation: path,
	}
}

func newPackageWithLicense(groupId, artifactId, version string, licenses []string, sourcePath string) model.Package {
	pkg := newPackage(groupId, artifactId, version, sourcePath)
	pkg.LicenseDeclared = licenses
	return *pkg
}

func packageURL(name, version string, groupID string) string {
	pURL := packageurl.NewPackageURL(
		PkgType(),
		strings.TrimSpace(groupID),
		strings.TrimSpace(name),
		strings.TrimSpace(version),
		nil,
		"")
	return pURL.ToString()
}

func normalize(groupId, artifactId, version string) (g, a, v string) {
	g = trim(groupId)
	a = trim(artifactId)
	v = trim(version)
	if hasBadStrs(g) {
		g = ""
	}
	if hasBadStrs(a) {
		a = ""
	}
	if hasBadStrs(v) {
		v = ""
	}
	return
}

func hasBadStrs(val string) bool {
	return util.SliceAny(badStrs, func(s string) bool {
		return strings.Contains(val, s)
	})
}

func trim(val string) string {
	val = strings.ReplaceAll(val, "%20", " ")
	return strings.TrimSpace(val)
}

func pkgNameRemoveEndTimestamp(val string) string {
	lastIndex := strings.LastIndex(val, "-")
	if lastIndex > 0 {
		return val[:lastIndex]
	}

	return val
}
