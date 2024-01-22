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

var pnpmLockTests = []struct {
	name    string
	args    args
	want    []model.Package
	want1   []model.Relationship
	wantErr bool
}{
	{
		name: "case-pnpm-v5",
		args: args{path: "test_material/pnpm/pnpm-v5.1.lock"},
		want: []model.Package{
			{
				Name:            "tslib",
				Version:         "2.3.0",
				Type:            PkgType(),
				PURL:            packageURL("tslib", "2.3.0"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/pnpm/pnpm-v5.1.lock",
			},
			{
				Name:            "wj-demo2",
				Version:         "1.1.3",
				Type:            PkgType(),
				PURL:            packageURL("wj-demo2", "1.1.3"),
				LicenseDeclared: nil,
				Dependencies:    []string{"pkg:npm/zrender@5.4.4"},
				SourceLocation:  "test_material/pnpm/pnpm-v5.1.lock",
			},
			{
				Name:            "zrender",
				Version:         "5.4.4",
				Type:            PkgType(),
				PURL:            packageURL("zrender", "5.4.4"),
				LicenseDeclared: nil,
				Dependencies:    []string{"pkg:npm/tslib@2.3.0"},
				SourceLocation:  "test_material/pnpm/pnpm-v5.1.lock",
			},
		},
		want1:   nil,
		wantErr: false,
	},
	{
		name: "case-pnpm-v6",
		args: args{path: "test_material/pnpm/pnpm.lock"},
		want: []model.Package{
			{
				Name:            "tslib",
				Version:         "2.3.0",
				Type:            PkgType(),
				PURL:            packageURL("tslib", "2.3.0"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/pnpm/pnpm.lock",
			},
			{
				Name:            "wj-demo2",
				Version:         "1.1.3",
				Type:            PkgType(),
				PURL:            packageURL("wj-demo2", "1.1.3"),
				LicenseDeclared: nil,
				Dependencies:    []string{"pkg:npm/zrender@5.4.4"},
				SourceLocation:  "test_material/pnpm/pnpm.lock",
			},
			{
				Name:            "zrender",
				Version:         "5.4.4",
				Type:            PkgType(),
				PURL:            packageURL("zrender", "5.4.4"),
				LicenseDeclared: nil,
				Dependencies:    []string{"pkg:npm/tslib@2.3.0"},
				SourceLocation:  "test_material/pnpm/pnpm.lock",
			},
		},
		want1:   nil,
		wantErr: false,
	},
}

func TestPnpmLockParser_Parse(t *testing.T) {
	for _, tt := range pnpmLockTests {
		t.Run(tt.name, func(t *testing.T) {
			pa := NewPnpmLockParser()
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

func BenchmarkPnpmLockParser(b *testing.B) {
	for _, tt := range pnpmLockTests {
		pa := NewPnpmLockParser()
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = pa.Parse(tt.args.path)
			}
		})
	}
}
