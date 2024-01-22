// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cargo

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestParseCargoLock(t *testing.T) {
	var expectStr string = `[
    {
        "name":"ansi_term",
        "version":"0.12.1",
        "type":"cargo",
        "purl":"pkg:cargo/ansi_term@0.12.1",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:cargo/winapi@0.3.9"
        ]
    },
    {
        "name":"matches",
        "version":"0.1.8",
        "type":"cargo",
        "purl":"pkg:cargo/matches@0.1.8",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    },
    {
        "name":"memchr",
        "version":"2.3.3",
        "type":"cargo",
        "purl":"pkg:cargo/memchr@2.3.3",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    },
    {
        "name":"natord",
        "version":"1.0.9",
        "type":"cargo",
        "purl":"pkg:cargo/natord@1.0.9",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    },
    {
        "name":"nom",
        "version":"4.2.3",
        "type":"cargo",
        "purl":"pkg:cargo/nom@4.2.3",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:cargo/memchr@2.3.3",
            "pkg:cargo/version_check@0.1.5"
        ]
    },
    {
        "name":"unicode-bidi",
        "version":"0.3.4",
        "type":"cargo",
        "purl":"pkg:cargo/unicode-bidi@0.3.4",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:cargo/matches@0.1.8"
        ]
    },
    {
        "name":"version_check",
        "version":"0.1.5",
        "type":"cargo",
        "purl":"pkg:cargo/version_check@0.1.5",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    },
    {
        "name":"winapi",
        "version":"0.3.9",
        "type":"cargo",
        "purl":"pkg:cargo/winapi@0.3.9",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[
            "pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0",
            "pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0"
        ]
    },
    {
        "name":"winapi-i686-pc-windows-gnu",
        "version":"0.4.0",
        "type":"cargo",
        "purl":"pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    },
    {
        "name":"winapi-x86_64-pc-windows-gnu",
        "version":"0.4.0",
        "type":"cargo",
        "purl":"pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0",
        "supplier":"",
        "filesAnalyzed":false,
        "verificationCode":"",
        "licenseConcluded":null,
        "licenseDeclared":null,
        "dependencies":[

        ]
    }
]`
	fixture := "test_material/Cargo.lock"
	parser := NewCargoFileParser()
	pkgs, err := parser.Parse(fixture)

	expectedPkgs := make([]model.Package, 0)

	err = json.Unmarshal([]byte(expectStr), &expectedPkgs)
	assert.NoError(t, err)

	if !slices.EqualFunc(expectedPkgs, pkgs, func(s1 model.Package, s2 model.Package) bool {
		return model.PackageEqual(&s1, &s2)
	}) {
		t.Errorf("Parse() got = %v, want %v", pkgs, expectedPkgs)
	}
}
