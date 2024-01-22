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

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

type testGradleitem struct {
	title    string
	filePath string
	expected []model.Package
}

var gradleFileTestdata = []testGradleitem{
	{
		title:    "Normal",
		filePath: "test_material/gradle/build.gradle",
		expected: []model.Package{
			{Name: "com.android.support.test/runner", Version: "1.0.1", Type: model.PkgTypeMaven},
			{Name: "com.android.support.constraint/constraint-layout", Version: "", Type: model.PkgTypeMaven},
			{Name: "joda-time/joda-time", Version: "2.2", Type: model.PkgTypeMaven},
		},
	},
}

func TestParseGradleFile(t *testing.T) {
	for _, item := range gradleFileTestdata {
		parse := NewJavaGradleFileParser()
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

var gradleLockTestdata = []testGradleitem{
	{
		title:    "Normal",
		filePath: "test_material/gradle/gradle.lockfile",
		expected: []model.Package{
			{Name: "ch.qos.logback/logback-classic", Version: "1.4.5", Type: model.PkgTypeMaven},
			{Name: "ch.epfl.scala/scalafix-interfaces", Version: "0.10.4", Type: model.PkgTypeMaven},
			{Name: "com.adtran/scala-multiversion-plugin", Version: "2.0.4", Type: model.PkgTypeMaven},
			{Name: "com.fasterxml.jackson/jackson-bom", Version: "2.11.0", Type: model.PkgTypeMaven},
			{Name: "com.github.alisiikh/gradle-scalastyle-plugin", Version: "3.4.1", Type: model.PkgTypeMaven},
		},
	},
}

func TestParseGradleLock(t *testing.T) {
	for _, item := range gradleLockTestdata {
		parse := NewJavaGradleLockParser()
		pkgs, _, err := parse.Parse(item.filePath)
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

func BenchmarkGradleFileParser(b *testing.B) {
	parse := NewJavaGradleFileParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/gradle/build.gradle")
	}
}

func BenchmarkGradleLockParser(b *testing.B) {
	parse := NewJavaGradleLockParser()
	for i := 0; i < b.N; i++ {
		_, _, _ = parse.Parse("test_material/gradle/gradle.lockfile")
	}
}
