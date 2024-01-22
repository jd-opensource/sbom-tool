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

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestParseMavenDependencyTreeFile(t *testing.T) {
	expected := `[
    {
        "name": "com.baomidou/mybatis-plus-boot-starter",
        "version": "3.5.0",
        "type": "maven",
        "purl": "pkg:maven/com.baomidou/mybatis-plus-boot-starter@3.5.0",
        "dependencies": [
            "pkg:maven/com.baomidou/mybatis-plus@3.5.0",
            "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.6.8"
        ]
    },
    {
        "name": "com.baomidou/mybatis-plus-core",
        "version": "3.5.0",
        "type": "maven",
        "purl": "pkg:maven/com.baomidou/mybatis-plus-core@3.5.0",
        "dependencies": [
            "pkg:maven/com.github.jsqlparser/jsqlparser@4.3"
        ]
    },
    {
        "name": "com.baomidou/mybatis-plus-extension",
        "version": "3.5.0",
        "type": "maven",
        "purl": "pkg:maven/com.baomidou/mybatis-plus-extension@3.5.0",
        "dependencies": [
            "pkg:maven/com.baomidou/mybatis-plus-core@3.5.0"
        ]
    },
    {
        "name": "com.baomidou/mybatis-plus",
        "version": "3.5.0",
        "type": "maven",
        "purl": "pkg:maven/com.baomidou/mybatis-plus@3.5.0",
        "dependencies": [
            "pkg:maven/com.baomidou/mybatis-plus-extension@3.5.0"
        ]
    },
    {
        "name": "com.github.jsqlparser/jsqlparser",
        "version": "4.3",
        "type": "maven",
        "purl": "pkg:maven/com.github.jsqlparser/jsqlparser@4.3",
        "dependencies": null
    },
    {
        "name": "mysql/mysql-connector-java",
        "version": "8.0.29",
        "type": "maven",
        "purl": "pkg:maven/mysql/mysql-connector-java@8.0.29",
        "dependencies": [
            "pkg:maven/com.baomidou/mybatis-plus@3.5.0"
        ]
    },
    {
        "name": "org.apache.logging.log4j/log4j-api",
        "version": "2.17.2",
        "type": "maven",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-api@2.17.2",
        "dependencies": null
    },
    {
        "name": "org.apache.logging.log4j/log4j-jul",
        "version": "2.17.2",
        "type": "maven",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-jul@2.17.2",
        "dependencies": null
    },
    {
        "name": "org.apache.logging.log4j/log4j-slf4j-impl",
        "version": "2.17.2",
        "type": "maven",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-slf4j-impl@2.17.2",
        "dependencies": [
            "pkg:maven/org.apache.logging.log4j/log4j-api@2.17.2"
        ]
    },
    {
        "name": "org.example/idolTrainee-common",
        "version": "1.0-SNAPSHOT",
        "type": "maven",
        "purl": "pkg:maven/org.example/idolTrainee-common@1.0-SNAPSHOT",
        "dependencies": [
            "pkg:maven/com.baomidou/mybatis-plus-boot-starter@3.5.0",
            "pkg:maven/mysql/mysql-connector-java@8.0.29",
            "pkg:maven/org.springframework.boot/spring-boot-starter-log4j2@2.6.8"
        ]
    },
    {
        "name": "org.example/test-dao",
        "version": "1.0-SNAPSHOT",
        "type": "maven",
        "purl": "pkg:maven/org.example/test-dao@1.0-SNAPSHOT",
        "dependencies": null
    },
    {
        "name": "org.example/test-service",
        "version": "1.0-SNAPSHOT",
        "type": "maven",
        "purl": "pkg:maven/org.example/test-service@1.0-SNAPSHOT",
        "dependencies": [
            "pkg:maven/org.example/test-dao@1.0-SNAPSHOT"
        ]
    },
    {
        "name": "org.example/test-web",
        "version": "1.0-SNAPSHOT",
        "type": "maven",
        "purl": "pkg:maven/org.example/test-web@1.0-SNAPSHOT",
        "dependencies": [
            "pkg:maven/org.example/idolTrainee-common@1.0-SNAPSHOT",
            "pkg:maven/org.example/test-service@1.0-SNAPSHOT"
        ]
    },
    {
        "name": "org.slf4j/jul-to-slf4j",
        "version": "1.7.36",
        "type": "maven",
        "purl": "pkg:maven/org.slf4j/jul-to-slf4j@1.7.36",
        "dependencies": null
    },
    {
        "name": "org.springframework.boot/spring-boot-autoconfigure",
        "version": "2.6.8",
        "type": "maven",
        "purl": "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.6.8",
        "dependencies": null
    },
    {
        "name": "org.springframework.boot/spring-boot-starter-log4j2",
        "version": "2.6.8",
        "type": "maven",
        "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-log4j2@2.6.8",
        "dependencies": [
            "pkg:maven/org.apache.logging.log4j/log4j-jul@2.17.2",
            "pkg:maven/org.apache.logging.log4j/log4j-slf4j-impl@2.17.2",
            "pkg:maven/org.slf4j/jul-to-slf4j@1.7.36"
        ]
    }
]
`
	path := "test_material/dependencyTree/tree2.txt"
	parser := NewDependencyTreeParser()
	pkgs, err := parser.Parse(path)
	if err != nil {
		t.Errorf("pkgs collect : +%v", err)
	}

	expectedPkgs := make([]model.Package, 0)

	err = json.Unmarshal([]byte(expected), &expectedPkgs)
	assert.NoError(t, err)

	if !slices.EqualFunc(expectedPkgs, pkgs, func(s1 model.Package, s2 model.Package) bool {
		return model.PackageEqual(&s1, &s2)
	}) {
		t.Errorf("Parse() got = %v, want %v", pkgs, expectedPkgs)
	}

}
