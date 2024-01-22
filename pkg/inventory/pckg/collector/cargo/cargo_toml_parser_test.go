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
	"reflect"
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestParseCargoToml(t *testing.T) {
	var expectStr string = `[
    {
        "name": "core",
        "version": "",
        "type": "cargo",
        "purl": "pkg:cargo/core",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "crossbeam",
        "version": "",
        "type": "cargo",
        "purl": "pkg:cargo/crossbeam",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "itertools",
        "version": "0.10",
        "type": "cargo",
        "purl": "pkg:cargo/itertools@0.10",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "rustorm-derive",
        "version": "0.1",
        "type": "cargo",
        "purl": "pkg:cargo/rustorm-derive@0.1",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "suspicious-pods-lib",
        "version": "1.2.0",
        "type": "cargo",
        "purl": "pkg:cargo/suspicious-pods-lib@1.2.0",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "suspicious-pods",
        "version": "1.2.0",
        "type": "cargo",
        "purl": "pkg:cargo/suspicious-pods@1.2.0",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    },
    {
        "name": "xi-core-lib",
        "version": "65911d9",
        "type": "cargo",
        "purl": "pkg:cargo/xi-core-lib@65911d9",
        "dependencies": null,
        "sourceLocation": "test_material/Cargo.toml"
    }
]
`
	expectPkgs := make([]model.Package, 0)
	json.Unmarshal([]byte(expectStr), &expectPkgs)

	fixture := "test_material/Cargo.toml"
	parser := NewCargoTomlFileParser()
	pkgs, err := parser.Parse(fixture)
	if err != nil {
		t.Errorf("err content:%+v", err)
	}

	if !reflect.DeepEqual(expectPkgs, pkgs) {
		t.Errorf("Parse() got = %v\n, want %v", pkgs, expectPkgs)
	}
}
