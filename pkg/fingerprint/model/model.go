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

// FileOutputMode is the output mode of fingerprint files.
type FileOutputMode string

const (
	OutputSingleFile FileOutputMode = "singlefile"
	OutputMultiFile  FileOutputMode = "multiplefile"
)

// Fingerprint of project.
type Fingerprint struct {
	Metadata Metadata          `json:"metadata"`
	Files    []FileFingerprint `json:"files"`
}

// Vendor of fingerprint.
type Vendor struct {
	Name        string `json:"name"`
	ToolName    string `json:"toolName"`
	ToolVersion string `json:"toolVersion"`
	AlgoName    string `json:"algoName"`
	AlgoVersion string `json:"algoVersion"`
}

// Repo of source code.
type Repo struct {
	URL      string `json:"url"`
	Branch   string `json:"branch"`
	Revision string `json:"revision"`
}

// Metadata of fingerprint.
type Metadata struct {
	TotalCount int64          `json:"totalCount"`
	TotalSize  int64          `json:"totalSize"`
	TotalFiles int64          `json:"totalFiles"`
	TotalLines int64          `json:"totalLines"`
	Language   []string       `json:"language"`
	CreatedAt  int64          `json:"createdAt"`
	OutputMode FileOutputMode `json:"outputMode"`
	Vendor     Vendor         `json:"vendor"`
	Repo       Repo           `json:"repo,omitempty"`
}

// SnippetFingerprint is fingerprint of snippet.
type SnippetFingerprint struct {
	Range string `json:"range"`
	Value string `json:"value"`
}

// FingerprintValue is fingerprint of file and snippets.
type FingerprintValue struct {
	File     string               `json:"file"`
	Snippets []SnippetFingerprint `json:"snippets"`
}

// FileFingerprint is metadata of file.
type FileFingerprint struct {
	File        string           `json:"file"`
	Size        int64            `json:"size"`
	Count       int64            `json:"count"`
	Lines       int64            `json:"lines"`
	License     []string         `json:"license"`
	Copyright   []string         `json:"copyright"`
	Language    string           `json:"language"`
	MD5         string           `json:"md5"`
	SHA1        string           `json:"sha1"`
	SHA256      string           `json:"sha256"`
	Fingerprint FingerprintValue `json:"fingerprint"`
}
