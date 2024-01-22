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

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestGoModFileParser_Parse(t *testing.T) {
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
			args{path: "test_material/gomod/go.mod"},
			[]model.Package{
				*newPackage("example.com/fork/net", "v1.4.5", "test_material/gomod/go.mod"),
				*newPackage("golang.org/x/net", "v1.2.1", "test_material/gomod/go.mod"),
				*newPackage("golang.org/x/net", "v1.2.5", "test_material/gomod/go.mod"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GoModFileParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Collect() got = %v, \nwant %v", got, tt.want)
			}
		})
	}
}

func BenchmarkGoModFileParser(b *testing.B) {
	g := GoModFileParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/go_mod_simple")
	}
}
