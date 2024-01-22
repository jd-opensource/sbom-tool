// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package carthage

import (
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestCartFileParser_Parse(t *testing.T) {
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
			"case-Cartfile",
			args{path: "test_material/Cartfile"},
			[]model.Package{
				newPackage("Mantle/Mantle", "1.0", ""),
				newPackage("ReactiveCocoa/ReactiveCocoa", "2.3.1", ""),
				newPackage("enterprise.local/desktop/git-error-translations2", "development", ""),
				newPackage("jspahrsummers/libextobjc", "0.4.1", ""),
				newPackage("jspahrsummers/xcconfigs", "branch", ""),
				newPackage("my.domain.com/release/MyFramework.json", "2.3", ""),
			},
			false,
		}, {
			"case-Cartfile.resolved",
			args{path: "test_material/Cartfile.resolved"},
			[]model.Package{
				newPackage("Mantle/Mantle", "1.3.0", ""),
				newPackage("ReactiveCocoa/ReactiveCocoa", "3.0.0", ""),
				newPackage("danielgindi/ios-charts", "3.0.0", ""),
				newPackage("enterprise.local/desktop/git-error-translations2", "8ff4393ede2ca86d5a78edaf62b3a14d90bffab9", ""),
				newPackage("enterprise.local/ghe/desktop/git-error-translations", "3.0.0", ""),
				newPackage("jspahrsummers/libextobjc", "0.4.1", ""),
				newPackage("jspahrsummers/objc-build-scripts", "3.0.0", ""),
				newPackage("jspahrsummers/xcconfigs", "1.3.0", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFile(tt.args.path)
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
