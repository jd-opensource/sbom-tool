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

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestParseJarNoDepFile(t *testing.T) {
	var jarTestdata = []testMavenitem{
		{
			title:    "Normal",
			filePath: "test_material/jar/example-java-jar-nodep-test-0.1.0.jar",
			expected: []model.Package{
				*newPackage("com.google.code.gson", "gson", "2.10.1", ""),
				newPackageWithLicense("org.sbom", "example-java-jar-nodep-test", "0.1.0", []string{"Apache-2.0"}, ""),
			},
		},
	}
	for _, item := range jarTestdata {
		parser := NewArchiveParser()
		pkgs, err := parser.Parse(item.filePath)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v \ngot %v", item.title, item.expected, pkgs)
		}
	}
}

func TestParseJarEmbeddedPomFile(t *testing.T) {
	var jarEmbeddedPomTestdata = []testMavenitem{
		{
			title:    "Normal",
			filePath: "test_material/jar/example-java-jar-embedded-pom-test-0.1.0.jar",
			expected: []model.Package{
				newPackageWithLicense("com.google.code.gson", "gson", "2.10.1", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("com.google.code.gson", "gson", "2.10.1", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("junit", "junit", "", nil, ""),
				newPackageWithLicense("org.sbom", "example-java-jar-embedded-pom-test", "0.1.0", []string{"Apache-2.0"}, ""),
			},
		},
	}
	for _, item := range jarEmbeddedPomTestdata {
		parser := NewArchiveParser()
		pkgs, err := parser.Parse(item.filePath)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v \ngot %v", item.title, item.expected, pkgs)
		}
	}
}

func TestParseJarEmbeddedJarFile(t *testing.T) {
	var jarEmbeddedJarTestdata = []testMavenitem{
		{
			title:    "Normal",
			filePath: "test_material/jar/example-java-jar-embedded-jar-test-0.1.0.jar",
			expected: []model.Package{
				newPackageWithLicense("com.google.code.gson", "gson", "2.10.1", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("com.google.code.gson", "gson", "2.10.1", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("org.sbom", "example-java-jar-embedded-jar-test", "0.1.0", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("", "spring-boot-jarmode-layertools", "2.7.1", []string{"Apache-2.0"}, ""),
			},
		},
	}
	for _, item := range jarEmbeddedJarTestdata {
		parser := NewArchiveParser()
		pkgs, err := parser.Parse(item.filePath)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v \ngot %v", item.title, item.expected, pkgs)
		}
	}
}

func BenchmarkArchiveParser(b *testing.B) {
	var jarTestdata = []testMavenitem{
		{
			title:    "Normal",
			filePath: "test_material/jar/example-java-jar-nodep-test-0.1.0.jar",
			expected: []model.Package{
				*newPackage("com.google.code.gson", "gson", "2.10.1", ""),
				newPackageWithLicense("org.sbom", "example-java-jar-nodep-test", "0.1.0", []string{"Apache-2.0"}, ""),
			},
		},
	}
	parser := NewArchiveParser()
	for _, item := range jarTestdata {
		for i := 0; i < b.N; i++ {
			_, err := parser.Parse(item.filePath)
			if err != nil {
				b.Errorf("test error[%v]: %e", item.title, err)
			}
		}
	}
}
