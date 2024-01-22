// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cocoapods

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestPodSpecParser_Parse(t *testing.T) {
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
			"case-1",
			args{path: "test_material/test.podspec"},
			[]model.Package{
				*newPackage("AFNetworking", "1.0", ""),
				*newPackage("RestKit/CoreData", "0.20.0", ""),
				*newPackage("MBProgressHUD", "0.5", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := PodSpecParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindSubString(t *testing.T) {

	specVar := findSub(specVarReg, " Pod::Spec.new  do  | spec1  | ")
	assert.Equal(t, "spec1", specVar)

	name := findSubString(nameReg, " spec.name = 'gemdemo' ")
	assert.Equal(t, "gemdemo", name)

	version := findSubString(versionReg, " spec.version = \"1.0.0\" ")
	assert.Equal(t, "1.0.0", version)

	dependency := findSubStringArray(dependencyReg, " spec.dependency \"example-gem\", \"~> 1.0\" ")
	assert.Equal(t, 2, len(dependency))
	if len(dependency) == 2 {
		assert.Equal(t, "example-gem", dependency[0])
		assert.Equal(t, "~> 1.0", dependency[1])
	}

}
