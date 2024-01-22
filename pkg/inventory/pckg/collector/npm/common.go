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
	"strings"

	"github.com/anchore/packageurl-go"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

var badStrs = []string{"$", "%", "*", ":"}
var badPrefixStrs = []string{"."}
var npmPrefix = "npm:"

func newPackage(name, version string, path string) *model.Package {
	name, version = normalize(name, version)
	if name == "" {
		return nil
	}
	return &model.Package{
		Name:           name,
		Version:        version,
		Type:           PkgType(),
		PURL:           packageURL(name, version),
		SourceLocation: path,
	}
}

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

func normalize(name, version string) (n, v string) {
	n = strings.TrimSpace(name)
	v = strings.TrimSpace(version)

	if strings.HasPrefix(v, npmPrefix) {
		nameAndVersion := v[len(npmPrefix):]
		versionSeparator := strings.LastIndex(nameAndVersion, "@")
		n = nameAndVersion[:versionSeparator]
		v = nameAndVersion[versionSeparator+1:]
		return n, v
	}

	if hasBadStrs(n) {
		n = ""
	}
	if hasBadPrefixStrs(n) {
		n = ""
	}
	if hasBadStrs(v) {
		v = ""
	}
	return n, v
}

func hasBadStrs(val string) bool {
	return util.SliceAny(badStrs, func(s string) bool {
		return strings.Contains(val, s)
	})
}

func hasBadPrefixStrs(val string) bool {
	return util.SliceAny(badPrefixStrs, func(s string) bool {
		return strings.HasPrefix(val, s)
	})
}
