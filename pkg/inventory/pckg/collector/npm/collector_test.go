// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package npm

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestNPMCollector_Collect(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult []model.Package
		wantErr    bool
	}{
		{
			name: "case-normal",
			files: []collector.File{
				collector.NewFileMeta("test_material/normal/package.json"),
				collector.NewFileMeta("test_material/normal/package-lock.json"),
			},
			wantResult: []model.Package{
				*newPackage("tslib", "2.3.0", ""),
				*newPackage("wj-demo2", "1.1.3", ""),
				{
					Name:            "wj-demo3",
					Version:         "8.8.2",
					Type:            model.PkgTypeNPM,
					PURL:            "pkg:npm/wj-demo3@8.8.2",
					LicenseDeclared: []string{"MIT"},
					Dependencies: []string{
						"pkg:npm/tslib@2.3.0",
						"pkg:npm/wj-demo2@1.1.3",
						"pkg:npm/zrender@5.4.3",
					},
				},
				*newPackage("zrender", "5.4.3", ""),
			},
			wantErr: false,
		},
		{
			name:  "case-one-lock",
			files: []collector.File{collector.NewFileMeta("test_material/normal/package-lock.json")},
			wantResult: []model.Package{
				{
					Name:            "tslib",
					Version:         "2.3.0",
					Type:            model.PkgTypeNPM,
					LicenseDeclared: nil,
					PURL:            "pkg:npm/tslib@2.3.0",
				},
				{
					Name:            "wj-demo2",
					Version:         "1.1.3",
					Type:            model.PkgTypeNPM,
					LicenseDeclared: nil,
					PURL:            "pkg:npm/wj-demo2@1.1.3",
				},
				{
					Name:            "wj-demo3",
					Version:         "8.8.2",
					Type:            model.PkgTypeNPM,
					LicenseDeclared: []string{"MIT"},
					PURL:            "pkg:npm/wj-demo3@8.8.2",
				},
				{
					Name:            "zrender",
					Version:         "5.4.3",
					Type:            model.PkgTypeNPM,
					LicenseDeclared: nil,
					PURL:            "pkg:npm/zrender@5.4.3",
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
				t.Errorf("Collect() gotResult = %v, \nwant %v", gotResult, tt.wantResult)
			}
		})
	}
}
