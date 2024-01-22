// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package golang

import (
	"github.com/anchore/packageurl-go"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
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
