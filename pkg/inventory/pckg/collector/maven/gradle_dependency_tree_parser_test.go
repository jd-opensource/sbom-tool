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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestParseGradleDependencyTreeFile(t *testing.T) {
	expected := `[
    {
        "name":"codescanner",
        "version":"",
        "type":"maven",
        "purl":"pkg:maven/codescanner",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/com.diffplug.spotless/spotless-plugin-gradle@6.6.0",
            "pkg:maven/com.github.ben-manes.caffeine/caffeine@3.1.6",
            "pkg:maven/gradle-junit-reports",
            "pkg:maven/io.vertx/vertx-core@4.2.5",
            "pkg:maven/org.apache.maven.shared/maven-dependency-analyzer@1.13.2"
        ]
    },
    {
        "name":"com.diffplug.spotless/spotless-plugin-gradle",
        "version":"6.6.0",
        "type":"maven",
        "purl":"pkg:maven/com.diffplug.spotless/spotless-plugin-gradle@6.6.0",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    },
    {
        "name":"com.github.ben-manes.caffeine/caffeine",
        "version":"3.1.6",
        "type":"maven",
        "purl":"pkg:maven/com.github.ben-manes.caffeine/caffeine@3.1.6",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    },
    {
        "name":"gradle-junit-reports",
        "version":"",
        "type":"maven",
        "purl":"pkg:maven/gradle-junit-reports",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.6.10"
        ]
    },
    {
        "name":"io.netty/netty-common",
        "version":"4.1.74.Final",
        "type":"maven",
        "purl":"pkg:maven/io.netty/netty-common@4.1.74.Final",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    },
    {
        "name":"io.vertx/vertx-core",
        "version":"4.2.5",
        "type":"maven",
        "purl":"pkg:maven/io.vertx/vertx-core@4.2.5",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/io.netty/netty-common@4.1.74.Final"
        ]
    },
    {
        "name":"org.apache.maven.shared/maven-dependency-analyzer",
        "version":"1.13.2",
        "type":"maven",
        "purl":"pkg:maven/org.apache.maven.shared/maven-dependency-analyzer@1.13.2",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/org.apache.maven/maven-core@3.2.5"
        ]
    },
    {
        "name":"org.apache.maven/maven-core",
        "version":"3.2.5",
        "type":"maven",
        "purl":"pkg:maven/org.apache.maven/maven-core@3.2.5",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/org.apache.maven/maven-model@3.9.1",
            "pkg:maven/org.apache.maven/maven-settings@3.9.1"
        ]
    },
    {
        "name":"org.apache.maven/maven-model",
        "version":"3.9.1",
        "type":"maven",
        "purl":"pkg:maven/org.apache.maven/maven-model@3.9.1",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:maven/org.codehaus.plexus/plexus-utils@3.5.1"
        ]
    },
    {
        "name":"org.apache.maven/maven-settings",
        "version":"3.9.1",
        "type":"maven",
        "purl":"pkg:maven/org.apache.maven/maven-settings@3.9.1",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    },
    {
        "name":"org.codehaus.plexus/plexus-utils",
        "version":"3.5.1",
        "type":"maven",
        "purl":"pkg:maven/org.codehaus.plexus/plexus-utils@3.5.1",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    },
    {
        "name":"org.jetbrains.kotlin/kotlin-stdlib",
        "version":"1.6.10",
        "type":"maven",
        "purl":"pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.6.10",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":null
    }
]`
	path := "test_material/gradle/gradle-dependency-tree3.txt"
	parser := NewGradleDependencyTreeParser()
	pkgs, err := parser.Parse(path)

	expectedPkgs := make([]model.Package, 0)

	err = json.Unmarshal([]byte(expected), &expectedPkgs)
	assert.NoError(t, err)

	if !slices.EqualFunc(expectedPkgs, pkgs, func(s1 model.Package, s2 model.Package) bool {
		return model.PackageEqual(&s1, &s2)
	}) {
		t.Errorf("Parse() got = %v, \nwant %v", pkgs, expectedPkgs)
	}
}
