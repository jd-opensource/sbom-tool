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
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	xspdxModel "gitee.com/jd-opensource/sbom-tool/pkg/spec/format/xspdx/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func (s *Spec) ToModel() *model.SBOM {
	spdxDoc := s.doc
	sbomDoc := &model.SBOM{
		NamespaceURI: spdxDoc.DocumentNamespace,
	}

	sbomDoc.CreationInfo = model.CreationInfo{
		Created: spdxDoc.CreationInfo.Created,
		Creators: util.SliceMap(spdxDoc.CreationInfo.Creators, func(c common.Creator) model.Creator {
			return model.Creator{Creator: c.Creator, CreatorType: c.CreatorType}
		}),
	}
	if spdxDoc.Source != nil {
		sbomDoc.Source = toSource(spdxDoc.Source)
	}
	if len(spdxDoc.Packages) > 0 {
		sbomDoc.Packages = util.SliceMap(spdxDoc.Packages, toPackage)
	}
	if spdxDoc.Artifact != nil {
		sbomDoc.Artifact = model.Artifact{
			Package: model.Package{Name: spdxDoc.Artifact.Name, Version: spdxDoc.Artifact.Version},
			Files:   util.SliceMap(spdxDoc.Files, toFile),
			Build:   toArtifactBuild(spdxDoc.Artifact.Build),
		}
	}

	if s.doc == nil {
		return nil
	}
	return sbomDoc
}

func toSource(src *xspdxModel.Source) model.Source {
	return model.Source{
		Repository:  src.Repository,
		Branch:      src.Branch,
		Revision:    src.Revision,
		TotalFile:   src.TotalFile,
		TotalLine:   src.TotalLine,
		TotalSize:   src.TotalSize,
		Language:    src.Language,
		Fingerprint: model.Fingerprint{},
	}
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

func toArtifactBuild(build *xspdxModel.Build) model.Build {
	return model.Build{
		OS:       build.OS,
		Arch:     build.Arch,
		Kernel:   build.Kernel,
		Builder:  build.Builder,
		Compiler: build.Compiler,
	}
}
