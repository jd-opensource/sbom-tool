// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package model

type ChecksumAlgorithm string

const (
	ChecksumMD5    ChecksumAlgorithm = "MD5"
	ChecksumSHA1   ChecksumAlgorithm = "SHA1"
	ChecksumSHA256 ChecksumAlgorithm = "SHA256"
)

// FileChecksum represents the checksum of the file
type FileChecksum struct {
	Algorithm ChecksumAlgorithm `json:"algorithm"`
	Value     string            `json:"value"`
}
