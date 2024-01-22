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
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestGvtManifestParser_Parse(t *testing.T) {
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
			args{path: "test_material/gvt/vendor/manifest"},
			[]model.Package{
				*newPackage("github.com/wadey/gocovmerge", "b5bfa59ec0adc420475f97f89b58045c721d761c", "test_material/gvt/vendor/manifest"),
				*newPackage("golang.org/x/tools", "8b84dae17391c154ca50b0162662aa1fc9ff84c2", "test_material/gvt/vendor/manifest"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GvtManifestParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {

				return collector.EqualPackage(&p1, &p2)
			}) {
				t.Errorf("Collect() got = %v, \nwant %v", got, tt.want)
			}

		})
	}
}

func BenchmarkGvtManifestParser(b *testing.B) {
	g := GvtManifestParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/gvt/vendor/manifest")
	}
}
