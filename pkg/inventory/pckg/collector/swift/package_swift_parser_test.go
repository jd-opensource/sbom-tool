// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package swift

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestParsePackageSwiftFile(t *testing.T) {
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
			"case-Package.swift-1",
			args{path: "test_material/Package.swift"},
			[]model.Package{
				newPackage("github.com/Carthage/Commandant", "0.16.0", ""),
				newPackage("github.com/Carthage/ReactiveTask", "0.16.0", ""),
				newPackage("github.com/Quick/Nimble", "8.0.1", ""),
				newPackage("github.com/Quick/Quick", "2.1.0", ""),
				newPackage("github.com/ReactiveCocoa/ReactiveSwift", "5.0.0", ""),
				newPackage("github.com/antitypical/Result", "4.1.0", ""),
				newPackage("github.com/apple/swift-argument-parser", "1.2.2", ""),
				newPackage("github.com/jdhealy/PrettyColors", "5.0.2", ""),
				newPackage("github.com/mdiep/Tentacle", "0.13.1", ""),
				newPackage("github.com/thoughtbot/Curry", "4.0.2", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePackageSwiftFile(tt.args.path)
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

func TestParsePackageResolvedFile(t *testing.T) {
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
			"case-Package.resolved-1",
			args{path: "test_material/Package.resolved"},
			[]model.Package{
				newPackage("github.com/Carthage/Commandant", "0.16.0", ""),
				newPackage("github.com/Carthage/ReactiveTask", "0.16.0", ""),
				newPackage("github.com/Quick/Nimble", "8.0.2", ""),
				newPackage("github.com/Quick/Quick", "2.1.0", ""),
				newPackage("github.com/ReactiveCocoa/ReactiveSwift", "5.0.1", ""),
				newPackage("github.com/antitypical/Result", "4.1.0", ""),
				newPackage("github.com/jdhealy/PrettyColors", "5.0.2", ""),
				newPackage("github.com/mdiep/Tentacle", "0.13.1", ""),
				newPackage("github.com/thoughtbot/Curry", "4.0.2", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePackageResolvedFile(tt.args.path)
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

func TestFindPackageReg(t *testing.T) {
	tests := []struct {
		name  string
		input string
		reg   *regexp.Regexp
		want  []string
	}{
		{
			"normal",
			`.package(url: "https://github.com/antitypical/Result.git", from: "4.1.0"),`,
			packageReg,
			[]string{`url: "https://github.com/antitypical/Result.git", from: "4.1.0"`},
		}, {
			"normal",
			`.package(url: "https://github.com/antitypical/Result.git", version: "", from: "4.1.0"),`,
			packageReg,
			[]string{`url: "https://github.com/antitypical/Result.git", version: "", from: "4.1.0"`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			got := test.reg.FindStringSubmatch(test.input)
			assert.Equal(tt, 2, len(got))
			assert.Equal(tt, test.want[0], got[1])
		})
	}
}
