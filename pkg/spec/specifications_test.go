// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package spec

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		format string
	}{
		{
			name:   "xspdx-json",
			file:   "format/xspdx/test_material/sbom.json",
			format: "xspdx-json",
		},
		{
			name:   "spdx-tagvalue",
			file:   "format/spdx/test_material/example-v2.3.spdx",
			format: "spdx-tagvalue",
		},
		{
			name:   "spdx-json",
			file:   "format/spdx/test_material/example-v2.3.spdx.json",
			format: "spdx-json",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open(test.file)
			assert.NoError(t, err, "open file %s", test.file)
			if err != nil {
				return
			}
			defer func(file *os.File) {
				_ = file.Close()
			}(file)
			sbomFormat, err := DetectFormat(file)
			assert.NoError(t, err, "load file %s", test.file)
			if err != nil {
				return
			}
			assert.NotNil(t, sbomFormat, "DetectFormat is nil")
			if sbomFormat == nil {
				return
			}
			assert.Equal(t, test.format, format.FormatName(sbomFormat))
		})
	}
}
