// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package gem

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestGemfileLockParser_Parse(t *testing.T) {
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
			"case-1",
			args{path: "test_material/Gemfile.lock"},
			"test_material/Gemfile-lock-out.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GemFileLockParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			data, err := os.ReadFile(tt.want)
			assert.NoError(t, err)

			expectPkgs := make([]model.Package, 0)
			err = json.Unmarshal(data, &expectPkgs)
			assert.NoError(t, err)

			if !util.SliceEqual(got, expectPkgs, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, \nwant %v", got, tt.want)
			}
		})
	}
}
