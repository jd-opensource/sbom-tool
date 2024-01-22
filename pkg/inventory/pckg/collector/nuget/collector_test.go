// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package nuget

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestNugetCollector_Parse(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult []model.Package
		wantErr    bool
	}{
		{
			name:  "case-1",
			files: []collector.File{collector.NewFileMeta("test_material/consoleTest.deps.json")},
			wantResult: []model.Package{
				*newPackage("Newtonsoft.Json", "13.0.3", ""),
				{
					Name:    "System.Banana",
					Version: "1.0.0",
					Type:    PkgType(),
					PURL:    packageURL("System.Banana", "1.0.0"),
					Dependencies: []string{
						newPackage("System.Foo", "1.0.0", "").PURL,
					},
				},
				{
					Name:    "System.Foo",
					Version: "1.0.0",
					Type:    PkgType(),
					PURL:    packageURL("System.Foo", "1.0.0"),
					Dependencies: []string{
						newPackage("Newtonsoft.Json", "13.0.3", "").PURL,
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewCollector()
			for i := range tt.files {
				g.TryToAccept(tt.files[i])
			}
			gotResult, err := g.Collect()
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(gotResult, tt.wantResult, func(p1 model.Package, p2 model.Package) bool {
				return collector.EqualPackage(&p1, &p2)
			}) {
				t.Errorf("Collect() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
