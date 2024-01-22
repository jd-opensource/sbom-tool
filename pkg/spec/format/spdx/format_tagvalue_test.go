// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package spdx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
)

func TestTagValueFormat_Load(t *testing.T) {
	spec := &Spec{}
	format := TagValueFormat{spec: spec}
	file, err := os.Open("test_material/example-v2.3.spdx")
	assert.NoError(t, err)
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	err = format.Load(file)
	assert.NoError(t, err)

	assert.Equal(t, "SPDX-Tools-v2.0", spec.doc.DocumentName)
	assert.Equal(t, v2_3.Version, spec.doc.SPDXVersion)
	assert.Equal(t, "DOCUMENT", string(spec.doc.SPDXIdentifier))
	assert.Equal(t, v2_3.DataLicense, spec.doc.DataLicense)
	assert.Equal(t, 5, len(spec.doc.Packages))
	assert.Equal(t, 4, len(spec.doc.Files))
}

func TestTagValueFormat_Dump(t *testing.T) {
	spec := &Spec{}
	format := TagValueFormat{spec: spec}

	spec.doc = newSpdxDoc()
	path := filepath.Join(os.TempDir(), "example-v2.3-new.spdx")
	file, err := os.Create(path)
	assert.NoError(t, err)
	err = format.Dump(file)
	assert.NoError(t, err)
}
