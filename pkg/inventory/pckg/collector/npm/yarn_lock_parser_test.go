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
	"reflect"
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

var yarnLockTests = []struct {
	name    string
	args    args
	want    []model.Package
	want1   []model.Relationship
	wantErr bool
}{
	{
		name: "case-yarnLock",
		args: args{path: "test_material/yarn/yarn.lock"},
		want: []model.Package{
			{
				Name:            "tslib",
				Version:         "2.3.0",
				Type:            PkgType(),
				PURL:            packageURL("tslib", "2.3.0"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/yarn/yarn.lock",
			},
			{
				Name:            "yarn",
				Version:         "1.22.19",
				Type:            PkgType(),
				PURL:            packageURL("yarn", "1.22.19"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/yarn/yarn.lock",
			},
			{
				Name:            "zrender",
				Version:         "5.4.4",
				Type:            PkgType(),
				PURL:            packageURL("zrender", "5.4.4"),
				LicenseDeclared: nil,
				Dependencies:    []string{"pkg:npm/tslib@2.3.0"},
				SourceLocation:  "test_material/yarn/yarn.lock",
			},
		},
		want1:   nil,
		wantErr: false,
	},
}

func TestYarnLockParser_Parse(t *testing.T) {
	for _, tt := range yarnLockTests {
		t.Run(tt.name, func(t *testing.T) {
			pa := NewYarnLockParser()
			got, err := pa.Parse(tt.args.path)
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

func BenchmarkYarnLockParser(b *testing.B) {
	for _, tt := range yarnLockTests {
		pa := NewYarnLockParser()
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = pa.Parse(tt.args.path)
			}
		})
	}
}
