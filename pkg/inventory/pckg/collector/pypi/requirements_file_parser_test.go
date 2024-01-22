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

type testRequirementsItem struct {
	title    string
	filePath string
	expected []model.Package
}

var requirementsTestdata = []testRequirementsItem{
	{
		title:    "requirements test",
		filePath: "test_material/requirements/requirements.txt",
		expected: []model.Package{
			{Name: "Flask-Bootstrap", Version: "3.3.6.0", Type: model.PkgTypePyPi},
			{Name: "Flask-Login", Version: "0.3.2", Type: model.PkgTypePyPi},
			{Name: "Flask-Migrate", Version: "1.8.1", Type: model.PkgTypePyPi},
			{Name: "Flask-Moment", Version: "0.5.1", Type: model.PkgTypePyPi},
			{Name: "Flask-Script", Version: "2.0.5", Type: model.PkgTypePyPi},
			{Name: "Flask-PageDown", Version: "0.2.1", Type: model.PkgTypePyPi},
			{Name: "Pandas", Version: "0.26.3", Type: model.PkgTypePyPi},
		},
	},
}

func TestParseRequirementsFile(t *testing.T) {
	for _, item := range requirementsTestdata {
		parse := NewRequirementsParser()
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

func BenchmarkRequirementsFileParser(b *testing.B) {
	parse := NewRequirementsParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/requirements/requirements.txt")
	}
}
