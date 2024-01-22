// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package xspdx

import (
	"testing"
	"time"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	xspdxModel "gitee.com/jd-opensource/sbom-tool/pkg/spec/format/xspdx/model"
)

func newXSPDXDoc() *xspdxModel.XSPDXDocument {
	doc := &xspdxModel.XSPDXDocument{}

	doc.Document = &v2_3.Document{
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
			{PackageName: "fastjson", PackageVersion: "1.2.78"},
		},
		Files: []*v2_3.File{
			{FileName: "a/b/c/d.java"},
		},
	}
	doc.Source = &xspdxModel.Source{
		Repository: "https://gitub.com/test/demo.git",
		Branch:     "release-v1.0.0",
		Revision:   "f88cc32b",
		TotalLine:  11,
		TotalFile:  111,
		Fingerprint: xspdxModel.Fingerprint{
			Vendor: xspdxModel.FingerprintVendor{
				Name:      "JD",
				Tool:      "sbom-tool (dev)",
				Algorithm: "simhash 1.0",
			},
		},
	}
	doc.Artifact = &xspdxModel.Artifact{
		Name:    "demo",
		Version: "1.0.0",
		Build: &xspdxModel.Build{
			OS:       "CentOS 7.6",
			Arch:     "x86_x64",
			Kernel:   "Linux 5.2.5",
			Builder:  "maven 3.4",
			Compiler: "javac",
		},
	}
	return doc
}

func newSbomDoc() *model.SBOM {
	return &model.SBOM{
		CreationInfo: model.CreationInfo{
			Creators: []model.Creator{
				{Creator: "sbom-tool", CreatorType: "Tool"},
			},
			Created: time.Now().Format(time.RFC3339),
		},
		Source: model.Source{
			Repository: "https://gitub.com/test/demo.git",
			Branch:     "release-v1.0.0",
			Revision:   "f88cc32b",
			TotalLine:  11,
			TotalFile:  111,
			Fingerprint: model.Fingerprint{
				Vendor: model.FingerprintVendor{
					Name:      "JD",
					Tool:      "sbom-tool (dev)",
					Algorithm: "simhash 1.0",
				},
			},
		},
		Packages: []model.Package{
			{Name: "fastjson", Version: "1.2.78", LicenseDeclared: []string{" AND MIT AND "}},
		},
		Artifact: model.Artifact{
			ID:      "",
			Package: model.Package{Name: "demo", Version: "1.0.0", LicenseDeclared: []string{" AND MIT"}},
			Files: []model.File{
				{Name: "a/b/c/d.java"},
			},
			Build: model.Build{OS: "CentOS 7.6", Arch: "x86_x64", Kernel: "Linux 5.2.5", Builder: "maven 3.4", Compiler: "javac"},
		},
	}
}

func TestXSPDXSpec_ToSBOM(t *testing.T) {
	xspdxDoc := newXSPDXDoc()
	xspdxSpec := &Spec{doc: xspdxDoc}

	sbomDoc := xspdxSpec.ToModel()

	assert.Equal(t, xspdxDoc.CreationInfo.Created, sbomDoc.CreationInfo.Created)
	assert.Equal(t, xspdxDoc.Source.Repository, sbomDoc.Source.Repository)
	assert.Equal(t, xspdxDoc.Source.Branch, sbomDoc.Source.Branch)
	assert.Equal(t, xspdxDoc.Source.Revision, sbomDoc.Source.Revision)
	assert.Equal(t, xspdxDoc.Artifact.Name, sbomDoc.Artifact.Name)
	assert.Equal(t, xspdxDoc.Artifact.Version, sbomDoc.Artifact.Version)
	assert.Equal(t, xspdxDoc.Artifact.Build.OS, sbomDoc.Artifact.Build.OS)
	assert.Equal(t, xspdxDoc.Artifact.Build.Arch, sbomDoc.Artifact.Build.Arch)
	assert.Equal(t, xspdxDoc.Artifact.Build.Kernel, sbomDoc.Artifact.Build.Kernel)
	assert.Equal(t, xspdxDoc.Artifact.Build.Builder, sbomDoc.Artifact.Build.Builder)
	assert.Equal(t, xspdxDoc.Artifact.Build.Compiler, sbomDoc.Artifact.Build.Compiler)
	assert.Equal(t, 1, len(sbomDoc.Packages))
	assert.Equal(t, 1, len(sbomDoc.Artifact.Files))
}

func TestXSPDXSpec_FromSBOM(t *testing.T) {
	xspdxSPec := &Spec{}
	sbomDoc := newSbomDoc()
	xspdxSPec.FromModel(sbomDoc)
	xspdxDoc := xspdxSPec.doc
	assert.Equal(t, sbomDoc.CreationInfo.Created, xspdxDoc.CreationInfo.Created)
	assert.Equal(t, sbomDoc.CreationInfo.Created, xspdxDoc.CreationInfo.Created)
	assert.Equal(t, sbomDoc.Source.Repository, xspdxDoc.Source.Repository)
	assert.Equal(t, sbomDoc.Source.Branch, xspdxDoc.Source.Branch)
	assert.Equal(t, sbomDoc.Source.Revision, xspdxDoc.Source.Revision)
	assert.Equal(t, sbomDoc.Artifact.Name, xspdxDoc.Artifact.Name)
	assert.Equal(t, sbomDoc.Artifact.Version, xspdxDoc.Artifact.Version)
	assert.Equal(t, sbomDoc.Artifact.Build.OS, xspdxDoc.Artifact.Build.OS)
	assert.Equal(t, sbomDoc.Artifact.Build.Arch, xspdxDoc.Artifact.Build.Arch)
	assert.Equal(t, sbomDoc.Artifact.Build.Kernel, xspdxDoc.Artifact.Build.Kernel)
	assert.Equal(t, sbomDoc.Artifact.Build.Builder, xspdxDoc.Artifact.Build.Builder)
	assert.Equal(t, sbomDoc.Artifact.Build.Compiler, xspdxDoc.Artifact.Build.Compiler)
	assert.Equal(t, "MIT", xspdxDoc.Artifact.LicenseDeclared)
	assert.Equal(t, 2, len(xspdxDoc.Packages))
	assert.Equal(t, 1, len(xspdxDoc.Files))
}

func TestToRelationships(t *testing.T) {
	type args struct {
		pkgs   []model.Package
		refPkg model.Package
	}
	tests := []struct {
		name string
		args args
		want []*spdx.Relationship
	}{
		{
			name: "",
			args: args{
				pkgs: []model.Package{
					{Name: "pkg1", Version: "1.0", Type: model.PkgTypeGeneric, PURL: "pkg:generic://pkg1@1.0"},
					{Name: "pkg2", Version: "1.0", Type: model.PkgTypeGeneric, PURL: "pkg:generic://pkg2@1.0", Dependencies: []string{
						"pkg:generic://pkg21@1.0",
					}},
					{Name: "pkg21", Version: "1.0", Type: model.PkgTypeGeneric, PURL: "pkg:generic://pkg21@1.0"},
				},
				refPkg: model.Package{Name: "Root", Version: "1.0"},
			},
			want: []*spdx.Relationship{
				{
					RefA:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("Root@1.0"))},
					RefB:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("pkg1@1.0"))},
					Relationship: spdx.RelationshipDependsOn,
				},
				{
					RefA:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("Root@1.0"))},
					RefB:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("pkg2@1.0"))},
					Relationship: spdx.RelationshipDependsOn,
				},
				{
					RefA:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("pkg2@1.0"))},
					RefB:         spdx.DocElementID{ElementRefID: spdx.ElementID("Package-" + SPDXID("pkg21@1.0"))},
					Relationship: spdx.RelationshipDependsOn,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toRelationships(tt.args.pkgs, &tt.args.refPkg)
			assert.Equalf(t, len(tt.want), len(got), "toFlatPackages(%v)", tt.args)
		})
	}
}
