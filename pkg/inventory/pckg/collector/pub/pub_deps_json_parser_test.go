// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pub

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func TestPubDepsJSONParser_Parse(t *testing.T) {
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
			"normal",
			args{path: "test_material/pub-deps.json"},
			"test_material/pub-deps-out.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewPubDepsJSONParser()
			gotPkgs, err := parser.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			data, err := os.ReadFile(tt.want)
			assert.NoError(t, err)

			expectPkgs := make([]model.Package, 0)
			err = json.Unmarshal(data, &expectPkgs)
			assert.NoError(t, err)

			if !util.SliceEqual(expectPkgs, gotPkgs, func(p1 model.Package, p2 model.Package) bool {
				return collector.EqualPackage(&p1, &p2)
			}) {
				t.Errorf("got=%v\nwant=%v", gotPkgs, expectPkgs)
			}
		})
	}
}

func BenchmarkPubDepsJSONParser(b *testing.B) {
	g := PubSpecLockParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/pub-deps.json")
	}
}
