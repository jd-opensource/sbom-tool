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
	"os"
	"path/filepath"
	"strings"

	"github.com/cavaliergopher/rpm"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

func collectRPM(cfg *config.ArtifactConfig) (*model.Artifact, error) {
	stat, err := os.Stat(cfg.DistPath)
	if err != nil {
		return nil, fmt.Errorf("dist path invalid: %w", err)
	}
	if stat.IsDir() || !strings.HasSuffix(cfg.DistPath, ".rpm") {
		return nil, fmt.Errorf("dist path is not rpm package")
	}

	file, err := os.Open(cfg.DistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open rpm file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	// Read the package headers
	rpmMeta, err := rpm.Read(file)
	if err != nil {
		log.Errorf("read rpm file error: %s", err.Error())
		return nil, err
	}
	mainPkg := model.Package{
		Name:     rpmMeta.Name(),
		Version:  versionRelease(rpmMeta.Version(), rpmMeta.Release()),
		Type:     model.PkgTypeRPM,
		Supplier: rpmMeta.Vendor(),
		PURL:     artifactPURL(model.PkgTypeDEB, "", rpmMeta.Name(), versionRelease(rpmMeta.Version(), rpmMeta.Release())),
	}
	license := strings.TrimSpace(rpmMeta.License())
	if license != "" {
		mainPkg.LicenseDeclared = []string{license}
	}
	files := make([]model.File, 0)
	rpmMd5, _ := util.MD5SumFile(cfg.DistPath)
	if cfg.ExtractFiles {
		for _, info := range rpmMeta.Files() {
			if info.IsDir() {
				continue
			}
			f := model.File{
				Name: info.Name(),
				Checksums: []model.FileChecksum{
					{
						Algorithm: model.ChecksumMD5,
						Value:     info.Digest(),
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
						Value:     rpmMd5,
					},
				},
			},
		}
	}
	mainPkg.VerificationCode = rpmMd5
	return &model.Artifact{
		ID:      rpmMd5,
		Package: mainPkg,
		Files:   files,
	}, nil
}

func versionRelease(version, release string) string {
	if version == "" && release == "" {
		return ""
	} else if release == "" {
		return version
	} else {
		return version + "-" + release
	}
}
