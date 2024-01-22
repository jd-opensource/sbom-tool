// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package artifact

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pault.ag/go/debian/deb"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/license"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

func collectDEB(cfg *config.ArtifactConfig) (*model.Artifact, error) {
	stat, err := os.Stat(cfg.DistPath)
	if err != nil {
		return nil, fmt.Errorf("dist path invalid: %w", err)
	}
	if stat.IsDir() || !strings.HasSuffix(cfg.DistPath, ".deb") {
		return nil, fmt.Errorf("dist path is not deb package")
	}

	// Read the package headers
	debFile, closer, err := deb.LoadFile(cfg.DistPath)
	if err != nil {
		log.Errorf("load deb package error: %s", err.Error())
		return nil, err
	}
	defer closer()
	mainPkg := model.Package{
		Name:    debFile.Control.Package,
		Version: debFile.Control.Version.String(),
		Type:    model.PkgTypeDEB,
		PURL:    artifactPURL(model.PkgTypeDEB, "debian", debFile.Control.Package, debFile.Control.Version.String()),
	}
	files := make([]model.File, 0)
	licenseList := make([]string, 0)
	debMd5, _ := util.MD5SumFile(cfg.DistPath)
	if cfg.ExtractFiles {
		for {
			header, err := debFile.Data.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Errorf("read deb data error: %s", err.Error())
				continue
			}
			info := header.FileInfo()
			if info.IsDir() {
				continue
			}
			if filepath.Base(header.Name) == license.CopyrightFileName {
				licenseList = license.GetLicensesFromCopyright(debFile.Data)
			}
			md5Sum, _ := util.MD5Sum(debFile.Data)
			f := model.File{
				Name: header.Name,
				Checksums: []model.FileChecksum{
					{
						Algorithm: model.ChecksumMD5,
						Value:     md5Sum,
					},
				},
			}
			files = append(files, f)
		}
	} else {
		files = []model.File{
			{
				Name: filepath.Base(cfg.DistPath),
				Checksums: []model.FileChecksum{
					{
						Algorithm: model.ChecksumMD5,
						Value:     debMd5,
					},
				},
			},
		}
	}
	mainPkg.LicenseDeclared = licenseList
	mainPkg.VerificationCode = debMd5
	return &model.Artifact{
		ID:      debMd5,
		Package: mainPkg,
		Files:   files,
	}, nil
}
