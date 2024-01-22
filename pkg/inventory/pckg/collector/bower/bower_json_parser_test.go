// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package bower

import (
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestBowerJSONParser_Parse(t *testing.T) {
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
			"case-bower.json-1",
			args{path: "test_material/bower.json"},
			[]model.Package{
				newPackage("eventEmitter", "4.2.11", ""),
				newPackage("get-size", "1.2.2", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewBowerJSONParser()
			got, err := parser.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, \nwant %v", got, tt.want)
			}
		})
	}
}
