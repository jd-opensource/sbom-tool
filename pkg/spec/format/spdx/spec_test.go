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
	"testing"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func newSpdxDoc() *v2_3.Document {
	return &v2_3.Document{
		DocumentName:   "SPDX-Tools-v2.0",
		SPDXVersion:    v2_3.Version,
		DataLicense:    v2_3.DataLicense,
		SPDXIdentifier: "DOCUMENT",
		CreationInfo: &v2_3.CreationInfo{
			LicenseListVersion: "1.1",
			Creators: []common.Creator{
				{Creator: "sbom-tool", CreatorType: "Tool"},
			},
			Created: time.Now().Format(time.RFC3339),
		},
		Packages: []*v2_3.Package{
			{PackageSPDXIdentifier: "SPDXRef-RootPackage", PackageName: "demo", PackageVersion: "1.0.0"},
			{PackageName: "fastjson", PackageVersion: "1.2.78"},
		},
		Files: []*v2_3.File{
			{FileName: "a/b/c/d.java"},
		},
	}
}

func newSbomDoc() *model.SBOM {
	return &model.SBOM{
		CreationInfo: model.CreationInfo{
			Creators: []model.Creator{
				{Creator: "sbom-tool", CreatorType: "Tool"},
			},
			Created: time.Now().Format(time.RFC3339),
		},
		Packages: []model.Package{
			{Name: "fastjson", Version: "1.2.78"},
		},
		Artifact: model.Artifact{
			ID:      "",
			Package: model.Package{Name: "demo", Version: "1.0.0"},
			Files: []model.File{
				{Name: "a/b/c/d.java"},
			},
		},
	}
}

func TestSpdxSpec_ToSBOM(t *testing.T) {
	spdxDoc := newSpdxDoc()
	spec := &Spec{doc: spdxDoc}

	sbomDoc := spec.ToModel()

	assert.Equal(t, spdxDoc.CreationInfo.Created, sbomDoc.CreationInfo.Created)
	assert.Equal(t, 2, len(sbomDoc.Packages))
	assert.Equal(t, 1, len(sbomDoc.Artifact.Files))
}

func TestSpdxSpec_FromSBOM(t *testing.T) {
	spec := &Spec{}
	sbomDoc := newSbomDoc()
	spec.FromModel(sbomDoc)

	spdxDoc := spec.doc
	assert.Equal(t, sbomDoc.CreationInfo.Created, spdxDoc.CreationInfo.Created)
	assert.Equal(t, 2, len(spdxDoc.Packages))
	assert.Equal(t, 1, len(spdxDoc.Files))
}
