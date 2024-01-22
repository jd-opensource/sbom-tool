// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pypi

import (
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

type testSetupItem struct {
	title    string
	filePath string
	expected []model.Package
}

var setUpTestdata = []testSetupItem{
	{
		title:    "setup.py test",
		filePath: "test_material/setup/setup.py",
		expected: []model.Package{
			{Name: "redis", Version: "2.10.5", Type: model.PkgTypePyPi},
			{Name: "setuptools", Version: "16.0", Type: model.PkgTypePyPi},
			{Name: "request2", Version: "2.0.2", Type: model.PkgTypePyPi},
			{Name: "url", Version: "0.4.2", Type: model.PkgTypePyPi},
		},
	},
}

func TestParseSetupFile(t *testing.T) {
	for _, item := range setUpTestdata {
		parse := NewSetUpParser()
		pkgs, err := parse.Parse(item.filePath)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !util.SliceEqual(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v got %v", item.title, item.expected, pkgs)
		}
	}
}

func BenchmarkSetUpFileParser(b *testing.B) {
	parse := NewRequirementsParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/setup/setup.py")
	}
}
