// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package source

import (
	"path/filepath"
	"time"

	gogit "github.com/go-git/go-git/v5"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/fingerprint"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

// GetSourceInfo returns the source information of the project
func GetSourceInfo(cfg *config.SourceConfig) (*model.Source, error) {
	fp, _ := fingerprint.CalcFingerprint(cfg)

	source := model.Source{
		TotalSize: fp.Metadata.TotalSize,
		TotalFile: fp.Metadata.TotalFiles,
		TotalLine: fp.Metadata.TotalLines,
		Fingerprint: model.Fingerprint{
			TotalCount:  fp.Metadata.TotalCount,
			Created:     time.UnixMilli(fp.Metadata.CreatedAt).Format(time.RFC3339),
			Checksum:    "",
			ExternalRef: "",
			Vendor: model.FingerprintVendor{
				Name:      fp.Metadata.Vendor.Name,
				Tool:      fp.Metadata.Vendor.ToolName + " " + fp.Metadata.Vendor.ToolVersion,
				Algorithm: fp.Metadata.Vendor.AlgoName + " " + fp.Metadata.Vendor.AlgoVersion,
			},
			Files: util.SliceMap(fp.Files, toSBOMFileFingerprint),
		},
	}
	repoInfo(cfg.SrcPath, &source)
	return &source, nil
}

func repoInfo(projectPath string, source *model.Source) {
	if len(projectPath) == 0 {
		return
	}
	repo, err := gogit.PlainOpen(projectPath)
	if err != nil {
		parentPath := filepath.Dir(projectPath)
		if parentPath == "." || parentPath == "/" || projectPath == parentPath {
			return
		}
		repoInfo(parentPath, source)
	} else {
		conf, err := repo.Config()
		if err == nil {
			if remote, ok := conf.Remotes["origin"]; ok {
				source.Repository = remote.URLs[0]
			}
		}
		ref, err := repo.Head()
		if err == nil {
			source.Branch = ref.Name().Short()
		}

		commit, err := repo.CommitObject(ref.Hash())
		if err == nil {
			source.Revision = commit.Hash.String()
		}
	}
}
