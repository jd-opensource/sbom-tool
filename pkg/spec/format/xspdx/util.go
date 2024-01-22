// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package xspdx

import (
	"github.com/spdx/tools-golang/spdx"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

// SPDXID returns the spdx id of the content
func SPDXID(content string) string {
	ret, _ := util.SHA1SumStr(content)
	return ret
}

// PackageSPDXID returns the spdx id of the package
func PackageSPDXID(pkg *model.Package) spdx.ElementID {
	return spdx.ElementID("Package-" + SPDXID(pkg.Name+"@"+pkg.Version))
}

// FileSPDXID returns the spdx id of the file
func FileSPDXID(file *model.File) spdx.ElementID {
	return spdx.ElementID("File-" + SPDXID(file.Name))
}
