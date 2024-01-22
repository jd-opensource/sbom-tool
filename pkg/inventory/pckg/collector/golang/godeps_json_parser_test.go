// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package golang

import (
	"reflect"
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestGodepsJSONParser_Parse(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []model.Package
		wantErr bool
	}{
		{
			"case-1",
			args{path: "test_material/godep/Godeps/Godeps.json"},
			[]model.Package{
				*newPackage("github.com/kr/fs", "2788f0dbd16903de03cb8186e5c7d97b69ad387b", "test_material/godep/Godeps/Godeps.json"),
				*newPackage("github.com/kr/pretty", "f31442d60e51465c69811e2107ae978868dbea5c", "test_material/godep/Godeps/Godeps.json"),
				*newPackage("github.com/kr/text", "6807e777504f54ad073ecef66747de158294b639", "test_material/godep/Godeps/Godeps.json"),
				*newPackage("github.com/pmezard/go-difflib/difflib", "f78a839676152fd9f4863704f5d516195c18fc14", "test_material/godep/Godeps/Godeps.json"),
				*newPackage("golang.org/x/tools/go/vcs", "", "test_material/godep/Godeps/Godeps.json"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GodepsJSONParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Collect() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkGodepsJSONParser(b *testing.B) {
	g := GodepsJSONParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/godep/Godeps/Godeps.json")
	}
}
