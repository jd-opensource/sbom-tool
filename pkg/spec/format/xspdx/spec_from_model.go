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
	"time"

	"github.com/spdx/tools-golang/spdx"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	xspdxModel "gitee.com/JD-opensource/sbom-tool/pkg/spec/format/xspdx/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/license"
)

var creatorTypes = []string{"Tool", "Person", "Organization"}

func (s *Spec) FromModel(sbomDoc *model.SBOM) {
	spdxDoc := &spdx.Document{
		SPDXVersion:       s.Version(),
		SPDXIdentifier:    "SPDXRef-DOCUMENT",
		DocumentName:      sbomDoc.Artifact.Name + "-" + sbomDoc.Artifact.Version,
		DocumentNamespace: sbomDoc.NamespaceURI,
		DataLicense:       "CC0-1.0",
	}
	creators := util.SliceFilter(sbomDoc.CreationInfo.Creators, func(creator model.Creator) bool {
		return util.SliceContains(creatorTypes, creator.CreatorType) && creator.Creator != ""
	})
	spdxDoc.CreationInfo = &spdx.CreationInfo{
		Creators: util.SliceMap(creators, func(c model.Creator) spdx.Creator {
			return spdx.Creator{
				CreatorType: c.CreatorType,
				Creator:     c.Creator,
			}
		}),
		Created: time.Now().Format(time.RFC3339),
	}

	spdxDoc.Packages = util.SliceMap(sbomDoc.Packages, fromPackage)
	spdxDoc.Packages = append(spdxDoc.Packages, fromPackage(sbomDoc.Artifact.Package))

	spdxDoc.Files = util.SliceMap(sbomDoc.Artifact.Files, fromFile)

	spdxDoc.Relationships = toRelationships(sbomDoc.Packages, &sbomDoc.Artifact.Package)
	s.doc = &xspdxModel.XSPDXDocument{
		Document: spdxDoc,
		Source:   fromSource(sbomDoc.Source),
		Artifact: fromArtifact(sbomDoc.Artifact),
	}
}

func toRelationships(pkgs []model.Package, mainPkg *model.Package) []*spdx.Relationship {
	mainPkgID := PackageSPDXID(mainPkg)
	pkgMap := make(map[string]*model.Package)
	allDeps := make(map[string]struct{})
	for i := 0; i < len(pkgs); i++ {
		pkgMap[pkgs[i].PURL] = &pkgs[i]
		for j := 0; j < len(pkgs[i].Dependencies); j++ {
			allDeps[pkgs[i].Dependencies[j]] = struct{}{}
		}
	}

	rels := make([]*spdx.Relationship, 0)
	for i := range pkgs {
		pkgID := PackageSPDXID(&pkgs[i])
		if _, isDep := allDeps[pkgs[i].PURL]; !isDep {
			rel := &spdx.Relationship{
				RefA:         spdx.DocElementID{ElementRefID: mainPkgID},
				RefB:         spdx.DocElementID{ElementRefID: pkgID},
				Relationship: spdx.RelationshipDependsOn,
			}
			rels = append(rels, rel)
		}

		if len(pkgs[i].Dependencies) > 0 {
			for _, dep := range pkgs[i].Dependencies {
				if pkg, ok := pkgMap[dep]; ok {
					rels = append(rels, &spdx.Relationship{
						RefA:         spdx.DocElementID{ElementRefID: pkgID},
						RefB:         spdx.DocElementID{ElementRefID: PackageSPDXID(pkg)},
						Relationship: spdx.RelationshipDependsOn,
					})
				}
			}
		}
	}
	return rels
}

func fromPackage(pkg model.Package) *spdx.Package {
	spdxPkg := &spdx.Package{
		PackageSPDXIdentifier:   PackageSPDXID(&pkg),
		PackageName:             pkg.Name,
		PackageVersion:          pkg.Version,
		PackageDownloadLocation: "NONE",
		PackageLicenseDeclared:  license.NOASSERTION_LICENSE,
		PackageLicenseConcluded: license.NOASSERTION_LICENSE,
	}
	if len(pkg.Supplier) > 0 {
		spdxPkg.PackageSupplier = &spdx.Supplier{
			Supplier:     pkg.Supplier,
			SupplierType: "Organization",
		}
	}
	if len(pkg.PURL) > 0 {
		spdxPkg.PackageExternalReferences = []*spdx.PackageExternalReference{
			{
				Category: "PACKAGE-MANAGER",
				RefType:  "PURL",
				Locator:  pkg.PURL,
			},
		}
	}
	if len(pkg.LicenseConcluded) > 0 {
		spdxPkg.PackageLicenseConcluded = license.CreateLicenseExpression(pkg.LicenseConcluded)
	}

	if len(pkg.LicenseDeclared) > 0 {
		spdxPkg.PackageLicenseDeclared = license.CreateLicenseExpression(pkg.LicenseDeclared)
	}
	return spdxPkg
}

func fromFile(file model.File) *spdx.File {
	return &spdx.File{
		FileSPDXIdentifier: FileSPDXID(&file),
		FileName:           file.Name,
		FileTypes:          []string{string(file.Type)},
		Checksums: util.SliceMap(file.Checksums, func(sum model.FileChecksum) spdx.Checksum {
			return spdx.Checksum{
				Algorithm: spdx.ChecksumAlgorithm(sum.Algorithm),
				Value:     sum.Value,
			}
		}),
	}
}

func fromSource(src model.Source) *xspdxModel.Source {
	return &xspdxModel.Source{
		Repository: src.Repository,
		Branch:     src.Branch,
		Revision:   src.Revision,
		TotalSize:  src.TotalSize,
		TotalLine:  src.TotalLine,
		TotalFile:  src.TotalFile,
		Language:   src.Language,
		Fingerprint: xspdxModel.Fingerprint{
			TotalCount:  src.Fingerprint.TotalCount,
			Created:     src.Fingerprint.Created,
			Checksum:    src.Fingerprint.Checksum,
			ExternalRef: src.Fingerprint.ExternalRef,
			OutputMode:  src.Fingerprint.OutputMode,
			Vendor: xspdxModel.FingerprintVendor{
				Name:      src.Fingerprint.Vendor.Name,
				Tool:      src.Fingerprint.Vendor.Tool,
				Algorithm: src.Fingerprint.Vendor.Algorithm,
			},
			Files: util.SliceMap(src.Fingerprint.Files, fromFileFingerprint),
		},
	}
}

func fromArtifact(artifact model.Artifact) *xspdxModel.Artifact {
	xspdxArtifact := &xspdxModel.Artifact{
		Name:             artifact.Name,
		Version:          artifact.Version,
		Type:             string(artifact.Type),
		PURL:             artifact.PURL,
		Supplier:         artifact.Supplier,
		Checksum:         artifact.VerificationCode,
		Build:            fromArtifactBuild(&artifact.Build),
		LicenseDeclared:  license.NOASSERTION_LICENSE,
		LicenseConcluded: license.NOASSERTION_LICENSE,
	}

	if len(artifact.LicenseDeclared) > 0 {
		xspdxArtifact.LicenseDeclared = license.CreateLicenseExpression(artifact.LicenseDeclared)
	}

	return xspdxArtifact
}

func fromArtifactBuild(build *model.Build) *xspdxModel.Build {
	return &xspdxModel.Build{
		OS:       build.OS,
		Arch:     build.Arch,
		Kernel:   build.Kernel,
		Builder:  build.Builder,
		Compiler: build.Compiler,
	}
}

func fromFileFingerprint(fileFP model.FileFingerprint) xspdxModel.FileFingerprint {
	return xspdxModel.FileFingerprint{
		File:      fileFP.File,
		Size:      fileFP.Size,
		Lines:     fileFP.Lines,
		Count:     fileFP.Count,
		Language:  fileFP.Language,
		Copyright: fileFP.Copyright,
		License:   fileFP.License,
		Checksums: util.SliceMap(fileFP.Checksums, func(sum model.FileChecksum) xspdxModel.FileChecksum {
			return xspdxModel.FileChecksum{Algorithm: xspdxModel.ChecksumAlgorithm(sum.Algorithm), Value: sum.Value}
		}),
		Fingerprint: xspdxModel.FingerprintValue{
			File: fileFP.Fingerprint.File,
			Snippet: util.SliceMap(fileFP.Fingerprint.Snippet, func(sfp model.SnippetFingerprint) xspdxModel.SnippetFingerprint {
				return xspdxModel.SnippetFingerprint{Range: sfp.Range, Value: sfp.Value}
			}),
		},
	}
}
