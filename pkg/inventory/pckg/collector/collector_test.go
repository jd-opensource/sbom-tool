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
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestOrganizePackage(t *testing.T) {
	data := []model.Package{
		{
			Name:            "gson",
			Type:            model.PkgTypeMaven,
			Version:         "1.0",
			LicenseDeclared: []string{"MIT"},
		},
		{
			Name:    "gson",
			Type:    model.PkgTypeMaven,
			Version: "2.0",
		},
		{
			Name:     "gson",
			Type:     model.PkgTypeRPM,
			Version:  "1.0",
			Supplier: "Google",
		},
		{
			Name:     "gson",
			Type:     model.PkgTypeMaven,
			Version:  "1.0",
			Supplier: "Google",
		},
		{
			Name:            "gson",
			Type:            model.PkgTypeMaven,
			Version:         "",
			LicenseDeclared: []string{"Apache2.0"},
		},
	}
	expect := []model.Package{
		{
			Name:            "gson",
			Type:            model.PkgTypeMaven,
			Version:         "1.0",
			LicenseDeclared: []string{"MIT"},
			Supplier:        "Google",
		},
		{
			Name:    "gson",
			Type:    model.PkgTypeMaven,
			Version: "2.0",
		},
		{
			Name:     "gson",
			Type:     model.PkgTypeRPM,
			Version:  "1.0",
			Supplier: "Google",
		},
	}

	result := OrganizePackage(data)
	expect = OrganizePackage(expect)

	equal := util.SliceEqual(result, expect, func(p1 model.Package, p2 model.Package) bool {
		return EqualPackage(&p1, &p2)
	})
	if !equal {
		t.Errorf("OrganizePackage() got = %v, \nwant %v", result, expect)
	}
}
