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

func TestGlideYAMLParser_Parse(t *testing.T) {
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
			args{path: "test_material/glide/glide.yml"},
			[]model.Package{
				*newPackage("github.com/Masterminds/semver", "1.4.0", "test_material/glide/glide.yml"),
				*newPackage("github.com/Masterminds/vcs", "1.13.1", "test_material/glide/glide.yml"),
				*newPackage("github.com/codegangsta/cli", "1.16.0", "test_material/glide/glide.yml"),
				*newPackage("github.com/mitchellh/go-homedir", "", "test_material/glide/glide.yml"),
				*newPackage("gopkg.in/yaml.v2", "", "test_material/glide/glide.yml"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GlideYAMLParser{}
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

func BenchmarkGlideYAMLParser(b *testing.B) {
	g := GoModFileParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/glide/glide.yml")
	}
}
