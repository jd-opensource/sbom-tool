// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ziputil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewZipFileManifest(t *testing.T) {
	tests := []struct {
		name    string
		zipPath string
		glob    string
		want    []string
	}{
		{
			"test glob",
			"test_material/DailyNote.jar",
			"**App.class",
			[]string{"com/dog/App.class"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, _ := ResolveFileManifest(tt.zipPath)
			match := manifest.GlobMatch(tt.glob)
			assert.Equal(t, tt.want, match)
		})
	}
}
