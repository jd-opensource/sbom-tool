// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package gem

import (
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func newPackage(name, version string, path string) *model.Package {
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

// spec\.name\s*=\s*(.*) , spec.name = "test"  ->  "test"
func findSub(re *regexp.Regexp, line string) string {
	m := re.FindStringSubmatch(line)
	if m == nil || len(m) <= 1 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// spec\.name\s*=\s*(.*) , spec.name = "test"  ->  test
func findSubString(re *regexp.Regexp, line string) string {
	str := findSub(re, line)
	m := strVarReg.FindStringSubmatch(str)
	if m == nil || len(m) <= 1 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// spec\.licenses\s*=\s*(.*), spec.licenses = ["MIT","Apache-2"]  ->  [MIT,Apache-2]
func findSubStringArray(re *regexp.Regexp, line string) []string {
	str := findSub(re, line)
	items := strings.Split(str, ",")
	ret := make([]string, 0)
	for _, it := range items {
		m := strVarReg.FindStringSubmatch(it)
		if m == nil || len(m) <= 1 {
			return nil
		}
		ret = append(ret, strings.TrimSpace(m[1]))
	}
	return ret
}

// "MIT","Apache-2"  ->  [MIT,Apache-2]
func parseStringArray(line string) []string {
	items := strings.Split(line, ",")
	ret := make([]string, 0)
	for _, it := range items {
		m := strVarReg.FindStringSubmatch(it)
		if m == nil || len(m) <= 1 {
			return nil
		}
		ret = append(ret, strings.TrimSpace(m[1]))
	}
	return ret
}

// ^~=<> 1.0.0  ->  1.0.0
func getVersion(ver string) string {
	return strings.TrimLeft(ver, "^~=<> ")
}
