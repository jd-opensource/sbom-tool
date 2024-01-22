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

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestGolangCollector_Collect(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult []model.Package
		wantErr    bool
	}{
		{
			name:  "case-1",
			files: []collector.File{collector.NewFileMeta("test_material/gomod/go.mod")},
			wantResult: []model.Package{
				*newPackage("example.com/fork/net", "v1.4.5", "test_material/gomod/go.mod"),
				*newPackage("golang.org/x/net", "v1.2.1", "test_material/gomod/go.mod"),
				*newPackage("golang.org/x/net", "v1.2.5", "test_material/gomod/go.mod"),
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
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("Collect() gotResult = %v, \nwant %v", gotResult, tt.wantResult)
			}
		})
	}
}
