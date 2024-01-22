// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"testing"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

type testMavenitem struct {
	title    string
	filePath string
	expected []model.Package
}

var pomTestdata = []testMavenitem{
	{
		title:    "Normal",
		filePath: "test_material/pom/pom.xml",
		expected: []model.Package{
			{Name: "org.antlr/antlr-runtime", Version: "3.5.2", Type: model.PkgTypeMaven},
			{Name: "org.tmatesoft.sqljet/sqljet", Version: "1.1.1", Type: model.PkgTypeMaven},
			{Name: "org.springframework.boot/spring-boot-starter-web", Version: "", Type: model.PkgTypeMaven},
			{Name: "group-1/artifact-1", Version: "", Type: model.PkgTypeMaven},
			{Name: "group-2/artifact-2", Version: "", Type: model.PkgTypeMaven},
		},
	},
}

func TestParsePomfile(t *testing.T) {

	for _, item := range pomTestdata {
		pkgs, err := parsePomFile(item.filePath)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v got %v", item.title, item.expected, pkgs)
		}
	}
}

func BenchmarkPomfileParser(b *testing.B) {
	parser := POMXMLParser{}
	for _, item := range pomTestdata {
		b.Run(item.title, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = parser.Parse(item.filePath)
			}
		})
	}
}
