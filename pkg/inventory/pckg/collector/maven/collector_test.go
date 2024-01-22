// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestMavenCollector_Collect(t *testing.T) {
	tests := []struct {
		name       string
		files      []collector.File
		wantResult []model.Package
		wantErr    bool
	}{
		{
			name: "case-archive",
			files: []collector.File{
				collector.NewFileMeta("test_material/jar/example-java-jar-nodep-test-0.1.0.jar"),
				collector.NewFileMeta("test_material/jar/example-java-jar-embedded-pom-test-0.1.0.jar"),
				collector.NewFileMeta("test_material/jar/example-java-jar-embedded-jar-test-0.1.0.jar"),
			},
			wantResult: []model.Package{
				newPackageWithLicense("com.google.code.gson", "gson", "2.10.1", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("junit", "junit", "", nil, ""),
				newPackageWithLicense("org.sbom", "example-java-jar-embedded-jar-test", "0.1.0", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("org.sbom", "example-java-jar-embedded-pom-test", "0.1.0", []string{"Apache-2.0"}, ""),
				newPackageWithLicense("org.sbom", "example-java-jar-nodep-test", "0.1.0", []string{"Apache-2.0"}, ""),
				func() model.Package {
					p := newPackageWithLicense("", "spring-boot-jarmode-layertools", "2.7.1", []string{"Apache-2.0"}, "")
					p.LicenseConcluded = p.LicenseDeclared
					return p
				}(),
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
			if !util.SliceEqual(gotResult, tt.wantResult, func(p1 model.Package, p2 model.Package) bool {
				return collector.EqualPackage(&p1, &p2)
			}) {
				t.Errorf("Collect() gotResult = %v, \nwant %v", gotResult, tt.wantResult)
			}
		})
	}
}
