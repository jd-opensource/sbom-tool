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
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func (s *Spec) ToModel() *model.SBOM {
	if s.doc == nil {
		return nil
	}
	spdxDoc := s.doc
	sbomDoc := &model.SBOM{
		NamespaceURI: spdxDoc.DocumentNamespace,
		CreationInfo: model.CreationInfo{
			Created: spdxDoc.CreationInfo.Created,
			Creators: util.SliceMap(spdxDoc.CreationInfo.Creators, func(c common.Creator) model.Creator {
				return model.Creator{Creator: c.Creator, CreatorType: c.CreatorType}
			}),
		},
	}

	sbomDoc.Packages = util.SliceMap(spdxDoc.Packages, toPackage)

	sbomDoc.Artifact = model.Artifact{
		Files: util.SliceMap(spdxDoc.Files, toFile),
	}
	index := util.SliceFirst(spdxDoc.Packages, func(p *spdx.Package) bool {
		return p.PackageSPDXIdentifier == "SPDXRef-RootPackage"
	})
	if index > -1 {
		sbomDoc.Artifact.Package = toPackage(spdxDoc.Packages[index])
	}

	return sbomDoc
}

func toPackage(pkg *spdx.Package) model.Package {
	purl := ""
	if len(pkg.PackageExternalReferences) > 0 {
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "" {
				purl = ref.Locator

				break
			}
		}
	}
	sbomPkg := model.Package{
		Name:    pkg.PackageName,
		Version: pkg.PackageVersion,
	}
	if purl != "" {
		sbomPkg.PURL = purl
	}
	// TODO license
	return sbomPkg
}

func toFile(file *spdx.File) model.File {
	return model.File{
		Name: file.FileName,
		Checksums: util.SliceMap(file.Checksums, func(sum spdx.Checksum) model.FileChecksum {
			return model.FileChecksum{Algorithm: model.ChecksumAlgorithm(sum.Algorithm), Value: sum.Value}
		}),
	}
}
