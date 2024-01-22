// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package composer

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

type testComposerJsonItem struct {
	title    string
	filePath string
	expected []model.Package
}

var composerJsonTestdata = []testComposerJsonItem{
	{
		title:    "testComposerJson test",
		filePath: "test_material/composer.json",
		expected: []model.Package{
			{Name: "fakerphp/faker1", Version: "1.29.1", Type: model.PkgTypeComposer},
			{Name: "fakerphp/faker2", Version: "1.0.0", Type: model.PkgTypeComposer},
			{Name: "fakerphp/faker3", Version: "4.4.1", Type: model.PkgTypeComposer},
			{Name: "fakerphp/faker4", Version: "4.4.2", Type: model.PkgTypeComposer},
			{Name: "guzzlehttp/guzzle", Version: "7.2", Type: model.PkgTypeComposer},
			{Name: "myclabs/php-enum", Version: "1.2.2", Type: model.PkgTypeComposer},
			{Name: "phan/phan", Version: "2.7.1", Type: model.PkgTypeComposer},
		},
	},
}

func TestParseComposerJsonFile(t *testing.T) {
	for _, item := range composerJsonTestdata {
		parse := NewComposerJsonFileParser()
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

func BenchmarkComposerJsonParser(b *testing.B) {
	parse := NewComposerJsonFileParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/composer.json")
	}
}
