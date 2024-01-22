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

func TestContentFromZip(t *testing.T) {
	tests := []struct {
		name    string
		zipPath string
		path    string
		want    string
	}{
		{
			"testing MANIFEST.MF",
			"test_material/DailyNote.jar",
			"META-INF/MANIFEST.MF",
			"Manifest-Version: 1.0\r\nProp1: 1234\r\nClass-Path: lib/fastjson-1.2.75.jar lib/commons-lang3-3.11.jar\r\nMain-Class: com.dog.App\r\n\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, _ := GetTextFromZip(tt.zipPath, tt.path)
			assert.Equal(t, tt.want, text)
		})
	}
}
