// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pub

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestPubSpecLockParser_Parse(t *testing.T) {
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
			"normal",
			args{path: "test_material/pubspec.lock"},
			[]model.Package{
				newPackage("collection", "1.15.0", ""),
				newPackage("cupertino_icons", "0.1.3", ""),
				newPackage("flutter", "0.0.0", ""),
				newPackage("flutter_markdown", "0.6.1", ""),
				newPackage("flutter_syntax_view", "3.2.2", ""),
				newPackage("flutter_web_plugins", "0.0.0", ""),
				newPackage("scoped_model", "1.1.0", ""),
				newPackage("shared_preferences", "2.0.5", ""),
				newPackage("shared_preferences_linux", "2.0.0", ""),
				newPackage("shared_preferences_macos", "2.0.0", ""),
				newPackage("shared_preferences_platform_interface", "2.0.0", ""),
				newPackage("shared_preferences_web", "2.0.0", ""),
				newPackage("shared_preferences_windows", "2.0.0", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := PubSpecLockParser{}
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

func BenchmarkPubSpecLockParser(b *testing.B) {
	g := PubSpecLockParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/pubspec.lock")
	}
}
