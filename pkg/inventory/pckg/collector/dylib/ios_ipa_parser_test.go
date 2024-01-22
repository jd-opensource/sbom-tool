// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dylib

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestIPAParser_Parse(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"case-ipa-1",
			args{path: "test_material/app.ipa"},
			"test_material/app_ipa_out.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewIPAParser()
			got, err := parser.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			bytes, err := os.ReadFile(tt.want)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := make([]model.Package, 0)
			err = json.Unmarshal(bytes, &want)
			if err != nil {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			marshal, err := json.Marshal(got)
			fmt.Println(string(marshal))
			if !util.SliceEqual(got, want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, \nwant %v", got, want)
			}
		})
	}
}

func TestParseDylibLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want model.Package
	}{
		{
			name: "@rpath",
			line: "@rpath/libswift_Concurrency.dylib (5.7.2)",
			want: newPackage("libswift_Concurrency", "5.7.2", ""),
		}, {
			name: "usr_lib",
			line: "/usr/lib/libobjc.A.dylib (228.0)",
			want: newPackage("libobjc.A", "228.0", ""),
		}, {
			name: "System_Library_Frameworks",
			line: "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (1949.0)",
			want: newPackage("CoreFoundation", "1949.0", ""),
		},
	}
	for i := 0; i < len(tests); i++ {
		test := tests[i]
		t.Run(test.name, func(tt *testing.T) {
			pkg := parseDylibLine(test.line, "")
			if !collector.EqualPackage(pkg, &test.want) {
				tt.Errorf("not equal, got = %v , \n want = %v", pkg, test.want)
			}
		})
	}
}
