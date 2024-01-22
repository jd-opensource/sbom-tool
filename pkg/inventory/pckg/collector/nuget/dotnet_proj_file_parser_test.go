// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package nuget

import (
	"testing"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestDotnetProjFileParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []model.Package
		wantErr bool
	}{
		{
			name: "case-1",
			path: "test_material/test.csproj",
			want: []model.Package{
				{
					Name:    "AutoMapper",
					Version: "12.0.1",
				},
				{
					Name:    "Basic.Reference.Assemblies.Net60",
					Version: "1.3.0",
				},
				{
					Name:    "Microsoft.CodeAnalysis.CSharp",
					Version: "4.7.0",
				},
				{
					Name:    "Microsoft.VisualStudio.Setup.Configuration.Interop",
					Version: "3.7.2175",
				},
				{
					Name:    "Microsoft.Win32.Registry",
					Version: "5.0.0",
				},
				{
					Name:    "Newtonsoft.Json",
					Version: "13.0.3",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewDotnetProjFileParser()
			got, err := g.Parse(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
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
