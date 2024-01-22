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

var packageLockTests = []struct {
	name    string
	args    args
	want    []model.Package
	want1   []model.Relationship
	wantErr bool
}{
	{
		name: "case-packageLock",
		args: args{path: "test_material/packageLock/packageLock.json"},
		want: []model.Package{
			{
				Name:            "tslib",
				Version:         "2.3.0",
				Type:            PkgType(),
				PURL:            packageURL("tslib", "2.3.0"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/packageLock/packageLock.json",
			},
			{
				Name:            "wj-demo2",
				Version:         "1.1.3",
				Type:            PkgType(),
				PURL:            packageURL("wj-demo2", "1.1.3"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/packageLock/packageLock.json",
			},
			{
				Name:            "wj-demo3",
				Version:         "8.8.2",
				Type:            PkgType(),
				PURL:            packageURL("wj-demo3", "8.8.2"),
				LicenseDeclared: []string{"MIT"},
				SourceLocation:  "test_material/packageLock/packageLock.json",
			},
			{
				Name:            "zrender",
				Version:         "5.4.3",
				Type:            PkgType(),
				PURL:            packageURL("zrender", "5.4.3"),
				LicenseDeclared: nil,
				SourceLocation:  "test_material/packageLock/packageLock.json",
			},
		},
		want1:   nil,
		wantErr: false,
	},
}

func TestPackageLockJsonParser_Parse(t *testing.T) {
	for _, tt := range packageLockTests {
		t.Run(tt.name, func(t *testing.T) {
			pa := PackageLockJSONParser{}
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

func Test_hasSubFolder(t *testing.T) {
	type args struct {
		path       string
		folderName string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"case-linux-style",
			args{path: "/foo/bar/1.txt", folderName: "bar"},
			true,
		},
		{
			"case-windows-style",
			args{path: "c:\\foo\\bar\\1.txt", folderName: "bar"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSubFolder(tt.args.path, tt.args.folderName); got != tt.want {
				t.Errorf("hasSubFolder() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkPackageLockParser(b *testing.B) {
	for _, tt := range packageLockTests {
		pa := PackageLockJSONParser{}
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = pa.Parse(tt.args.path)
			}
		})
	}
}
