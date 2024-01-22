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

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

type testPythonMetadataItem struct {
	title    string
	filePath string
	expected []model.Package
}

var eggPkgInfoTestdata = []testPythonMetadataItem{
	{
		title:    "egg PKG-INFO test",
		filePath: "test_material/egg/PKG-INFO",
		expected: []model.Package{
			{Name: "testlib", Version: "1.0.0", Type: model.PkgTypePyPi, LicenseDeclared: []string{"UNKNOWN"}},
		},
	},
}

var distMetadataInfoTestdata = []testPythonMetadataItem{
	{
		title:    "distInfo METADATA test",
		filePath: "test_material/whl/METADATA",
		expected: []model.Package{
			{Name: "BeautifulSoup", Version: "3.2.2", Type: model.PkgTypePyPi, LicenseDeclared: []string{"MIT"}},
		},
	},
}

func TestParsePkgInfoFile(t *testing.T) {
	for _, item := range eggPkgInfoTestdata {
		parse := NewPkgMetadataParser()
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

func TestParseDistMetadataInfoFile(t *testing.T) {
	for _, item := range distMetadataInfoTestdata {
		parse := NewPkgMetadataParser()
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

func BenchmarkPkgInfoFileParser(b *testing.B) {
	parse := NewPkgMetadataParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/egg/PKG-INFO")
	}
}

func BenchmarkDistMetadataInfoFileParser(b *testing.B) {
	parse := NewPkgMetadataParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/whl/METADATA")
	}
}
