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

	"github.com/stretchr/testify/assert"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
)

func TestPriorityResolutionCargoFile_Parse(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult string
		wantErr    bool
	}{
		{
			name: "case-1",
			files: []collector.File{
				collector.NewFileMeta("test_material/Cargo.toml"),
			},
			wantResult: `[{"name":"core","version":"","type":"cargo","purl":"pkg:cargo/core","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"crossbeam","version":"","type":"cargo","purl":"pkg:cargo/crossbeam","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"itertools","version":"0.10","type":"cargo","purl":"pkg:cargo/itertools@0.10","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"rustorm-derive","version":"0.1","type":"cargo","purl":"pkg:cargo/rustorm-derive@0.1","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"suspicious-pods-lib","version":"1.2.0","type":"cargo","purl":"pkg:cargo/suspicious-pods-lib@1.2.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"suspicious-pods","version":"1.2.0","type":"cargo","purl":"pkg:cargo/suspicious-pods@1.2.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"},{"name":"xi-core-lib","version":"65911d9","type":"cargo","purl":"pkg:cargo/xi-core-lib@65911d9","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":null,"sourceLocation":"test_material/Cargo.toml"}]`,
			wantErr:    false,
		},
		{
			name: "case-2",
			files: []collector.File{
				collector.NewFileMeta("test_material/Cargo.lock"),
			},
			wantResult: `[{"name":"ansi_term","version":"0.12.1","type":"cargo","purl":"pkg:cargo/ansi_term@0.12.1","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":["pkg:cargo/winapi@0.3.9"],"sourceLocation":"test_material/Cargo.lock"},{"name":"matches","version":"0.1.8","type":"cargo","purl":"pkg:cargo/matches@0.1.8","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"},{"name":"memchr","version":"2.3.3","type":"cargo","purl":"pkg:cargo/memchr@2.3.3","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"},{"name":"natord","version":"1.0.9","type":"cargo","purl":"pkg:cargo/natord@1.0.9","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"},{"name":"nom","version":"4.2.3","type":"cargo","purl":"pkg:cargo/nom@4.2.3","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":["pkg:cargo/memchr@2.3.3","pkg:cargo/version_check@0.1.5"],"sourceLocation":"test_material/Cargo.lock"},{"name":"unicode-bidi","version":"0.3.4","type":"cargo","purl":"pkg:cargo/unicode-bidi@0.3.4","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":["pkg:cargo/matches@0.1.8"],"sourceLocation":"test_material/Cargo.lock"},{"name":"version_check","version":"0.1.5","type":"cargo","purl":"pkg:cargo/version_check@0.1.5","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"},{"name":"winapi","version":"0.3.9","type":"cargo","purl":"pkg:cargo/winapi@0.3.9","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":["pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0","pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0"],"sourceLocation":"test_material/Cargo.lock"},{"name":"winapi-i686-pc-windows-gnu","version":"0.4.0","type":"cargo","purl":"pkg:cargo/winapi-i686-pc-windows-gnu@0.4.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"},{"name":"winapi-x86_64-pc-windows-gnu","version":"0.4.0","type":"cargo","purl":"pkg:cargo/winapi-x86_64-pc-windows-gnu@0.4.0","supplier":"","filesAnalyzed":false,"verificationCode":"","licenseConcluded":null,"licenseDeclared":null,"dependencies":[],"sourceLocation":"test_material/Cargo.lock"}]`, wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewCollector()
			for i := range tt.files {
				g.TryToAccept(tt.files[i])
			}
			pkgs, err := g.Collect()
			assert.NoError(t, err)
			gotResult, err := json.Marshal(pkgs)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(string(gotResult), tt.wantResult) {
				t.Errorf("Collect() gotResult = %v, want %v", string(gotResult), tt.wantResult)
			}
		})
	}
}
