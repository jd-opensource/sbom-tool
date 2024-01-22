// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conan

import (
	"testing"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestConanCollector_Parse(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult []model.Package
		wantErr    bool
	}{
		{
			name:  "case-1",
			files: []collector.File{collector.NewFileMeta("test_material/conan/conanfile.txt")},
			wantResult: []model.Package{
				{
					Name: "zlib", Version: "1.2.11",
					PURL:            "pkg:conan/zlib@1.2.11",
					LicenseDeclared: []string{},
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
			if !slices.EqualFunc(gotResult, tt.wantResult, func(s1 model.Package, s2 model.Package) bool {
				return model.PackageEqual(&s1, &s2)
			}) {
				t.Errorf("Collect() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
