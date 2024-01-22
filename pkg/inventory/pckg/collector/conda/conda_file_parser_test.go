// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conda

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

type testCondaItem struct {
	title    string
	filePath string
	expected []model.Package
}

var condaEnvironmentTestdata = []testCondaItem{
	{
		title:    "test environment.yml test",
		filePath: "test_material/environment.yml",
		expected: []model.Package{
			{Name: "_libgcc_mutex", Version: "0.1", Type: model.PkgTypeConda},
			{Name: "blas", Version: "1.0", Type: model.PkgTypeConda},
			{Name: "certifi", Version: "2022.12.7", Type: model.PkgTypeConda},
			{Name: "dlib", Version: "19.19.0", Type: model.PkgTypeConda},
			{Name: "pyqt5-sip", Version: "4.19.18", Type: model.PkgTypeConda},
		},
	},
}

func TestParseCondaEnvironmentFile(t *testing.T) {
	for _, item := range condaEnvironmentTestdata {
		parse := NewCondaFileParser()
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

var condaPackageListTestdata = []testCondaItem{
	{
		title:    "test package-list.txt test",
		filePath: "test_material/package-list.txt",
		expected: []model.Package{
			{Name: "asn1crypto", Version: "0.24.0", Type: model.PkgTypeConda},
			{Name: "ca-certificates", Version: "2019.1.23", Type: model.PkgTypeConda},
			{Name: "certifi", Version: "2019.3.9", Type: model.PkgTypeConda},
			{Name: "cffi", Version: "1.11.5", Type: model.PkgTypeConda},
			{Name: "chardet", Version: "3.0.4", Type: model.PkgTypeConda},
		},
	},
}

func TestParseCondaPackageListFile(t *testing.T) {
	for _, item := range condaPackageListTestdata {
		parse := NewCondaFileParser()
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

func BenchmarkCondaParser(b *testing.B) {
	parse := NewCondaFileParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/environment.yml")
	}
}
