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
	"time"

	"gitee.com/JD-opensource/sbom-tool/pkg/fingerprint/model"
	model3 "gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func ConvertFingerprint(fp *model.Fingerprint) *model3.Source {
	return &model3.Source{
		TotalSize: fp.Metadata.TotalSize,
		TotalFile: fp.Metadata.TotalFiles,
		TotalLine: fp.Metadata.TotalLines,
		Fingerprint: model3.Fingerprint{
			TotalCount:  fp.Metadata.TotalCount,
			Created:     time.UnixMilli(fp.Metadata.CreatedAt).Format(time.RFC3339),
			Checksum:    "",
			ExternalRef: "",
			Vendor: model3.FingerprintVendor{
				Name:      fp.Metadata.Vendor.Name,
				Tool:      fp.Metadata.Vendor.ToolName + " " + fp.Metadata.Vendor.ToolVersion,
				Algorithm: fp.Metadata.Vendor.AlgoName + " " + fp.Metadata.Vendor.AlgoVersion,
			},
			Files: util.SliceMap(fp.Files, toSBOMFileFingerprint),
		},
	}
}

func toSBOMFileFingerprint(fp model.FileFingerprint) model3.FileFingerprint {
	checksums := make([]model3.FileChecksum, 0)
	if len(fp.MD5) > 0 {
		checksums = append(checksums, model3.FileChecksum{
			Algorithm: model3.ChecksumMD5,
			Value:     fp.MD5,
		})
	}
	if len(fp.SHA1) > 0 {
		checksums = append(checksums, model3.FileChecksum{
			Algorithm: model3.ChecksumSHA1,
			Value:     fp.SHA1,
		})
	}
	if len(fp.SHA256) > 0 {
		checksums = append(checksums, model3.FileChecksum{
			Algorithm: model3.ChecksumSHA256,
			Value:     fp.SHA256,
		})
	}
	return model3.FileFingerprint{
		File:      fp.File,
		Size:      fp.Size,
		Lines:     fp.Lines,
		Count:     fp.Count,
		Language:  fp.Language,
		Copyright: fp.Copyright,
		Checksums: checksums,
		Fingerprint: model3.FingerprintValue{
			File: fp.Fingerprint.File,
			Snippet: util.SliceMap(fp.Fingerprint.Snippets, func(sfp model.SnippetFingerprint) model3.SnippetFingerprint {
				return model3.SnippetFingerprint{
					Range: sfp.Range,
					Value: sfp.Value,
				}
			}),
		},
	}
}
