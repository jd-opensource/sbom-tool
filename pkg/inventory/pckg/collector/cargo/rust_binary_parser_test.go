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
)

func TestParseRustBinaryFile(t *testing.T) {
	expectStr := `[{"name":"crate_with_features","version":"0.1.0","type":"cargo","purl":"pkg:cargo/crate_with_features@0.1.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/test.exe"},{"name":"library_crate","version":"0.1.0","type":"cargo","purl":"pkg:cargo/library_crate@0.1.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/test.exe"}]`
	fixture := "test_material/test.exe"
	parser := NewRustBinaryParser()
	pkgs, err := parser.Parse(fixture)
	if err != nil {
		t.Errorf("err content:%+v", err)
	}
	realStr, _ := json.Marshal(pkgs)
	if !reflect.DeepEqual(expectStr, string(realStr)) {
		t.Errorf("Parse() got = %v\n, want %v", string(realStr), expectStr)
	}
}
