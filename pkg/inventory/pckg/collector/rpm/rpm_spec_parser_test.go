// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package rpm

import (
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestRPMSpecFileParser_Parse(t *testing.T) {
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
			args{path: "test_material/test.spec"},
			[]model.Package{
				newPackage("clang", "3.0.0", "test_material/test.spec"),
				newPackage("gcc", "", "test_material/test.spec"),
				newPackage("gettext", "", "test_material/test.spec"),
				newPackage("git-devel", "", "test_material/test.spec"),
				newPackage("glibc", "2.2.2", "test_material/test.spec"),
				newPackage("make", "", "test_material/test.spec"),
				newPackage("python3", "", "test_material/test.spec"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := RPMSpecFileParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBuildRequires(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []model.Package
	}{
		{
			name:  "multiple",
			input: "clang python",
			want: []model.Package{
				newPackage("clang", "", ""),
				newPackage("python", "", ""),
			},
		},
		{
			name:  "version",
			input: "clang >= 1.10.1",
			want: []model.Package{
				newPackage("clang", "1.10.1", ""),
			},
		},
		{
			name:  "complex",
			input: "glibc = 1.0.0 clang >= 1.10.1, python",
			want: []model.Package{
				newPackage("glibc", "1.0.0", ""),
				newPackage("clang", "1.10.1", ""),
				newPackage("python", "", ""),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := parseBuildRequires(tt.input, "")

			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("parseBuildRequires() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkRPMSpecFileParser(b *testing.B) {
	g := RPMSpecFileParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/test.spec")
	}
}
