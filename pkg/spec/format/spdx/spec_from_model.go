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
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
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
		DataLicense:       spdx.DataLicense,
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

	spdxDoc.Packages = util.SliceMap(sbomDoc.Packages, toSpdxPackage)
	spdxDoc.Packages = append(spdxDoc.Packages, toSpdxPackage(sbomDoc.Artifact.Package))

	spdxDoc.Files = util.SliceMap(sbomDoc.Artifact.Files, toSpdxFile)
	spdxDoc.Relationships = toRelationships(sbomDoc.Packages, &sbomDoc.Artifact.Package)
	s.doc = spdxDoc
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

func toSpdxPackage(pkg model.Package) *spdx.Package {
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
		spdxPkg.PackageLicenseConcluded = licenseExpressionForSpdx(pkg.LicenseConcluded)
	}

	if len(pkg.LicenseDeclared) > 0 {
		spdxPkg.PackageLicenseDeclared = licenseExpressionForSpdx(pkg.LicenseDeclared)
	}
	return spdxPkg
}

func toSpdxFile(file model.File) *spdx.File {
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

func licenseExpressionForSpdx(licenses []string) string {
	licenseExpression := strings.Join(licenses, " AND ")
	return licenseExpression
}
