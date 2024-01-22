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

type Language string

const (
	Language_Unknown    Language = ""
	Language_CPP        Language = "c++"
	Language_Dart       Language = "dart"
	Language_Dotnet     Language = "dotnet"
	Language_Elixir     Language = "elixir"
	Language_Erlang     Language = "erlang"
	Language_Go         Language = "go"
	Language_Haskell    Language = "haskell"
	Language_Java       Language = "java"
	Language_JavaScript Language = "javascript"
	Language_PHP        Language = "php"
	Language_Python     Language = "python"
	Language_Ruby       Language = "ruby"
	Language_Rust       Language = "rust"
	Language_Swift      Language = "swift"
)

type ChecksumAlgorithm string

const Checksum_MD5 ChecksumAlgorithm = "MD5"
const Checksum_SHA1 ChecksumAlgorithm = "SHA1"
const Checksum_SHA256 ChecksumAlgorithm = "SHA256"

// FileChecksum represents the checksum of the file
type FileChecksum struct {
	Algorithm ChecksumAlgorithm `json:"algorithm"`
	Value     string            `json:"checksumValue"`
}
type Source struct {
	Repository  string      `json:"repository,omitempty"`
	Branch      string      `json:"branch,omitempty"`
	Revision    string      `json:"revision,omitempty"`
	TotalSize   int64       `json:"totalSize,omitempty"`
	TotalFile   int64       `json:"totalFile,omitempty"`
	TotalLine   int64       `json:"totalLine,omitempty"`
	Language    []string    `json:"language,omitempty"`
	Fingerprint Fingerprint `json:"fingerprint,omitempty"`
}
type FingerprintVendor struct {
	Name      string `json:"name,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

type Fingerprint struct {
	TotalCount  int64             `json:"totalCount,omitempty"`
	Created     string            `json:"created,omitempty"`
	Checksum    string            `json:"checksum,omitempty"`
	OutputMode  string            `json:"outputMode,omitempty"`
	ExternalRef string            `json:"externalRef,omitempty"`
	Vendor      FingerprintVendor `json:"vendor,omitempty"`
	Files       []FileFingerprint `json:"files,omitempty"`
}
type FileFingerprint struct {
	File        string           `json:"file,omitempty"`
	Size        int64            `json:"size,omitempty"`
	Lines       int64            `json:"lines,omitempty"`
	Count       int64            `json:"count,omitempty"`
	License     string           `json:"license,omitempty"`
	Copyright   []string         `json:"copyright,omitempty"`
	Language    string           `json:"language,omitempty"`
	Checksums   []FileChecksum   `json:"checksums,omitempty"`
	Fingerprint FingerprintValue `json:"fingerprint,omitempty"`
}

type FingerprintValue struct {
	File    string               `json:"file,omitempty"`
	Snippet []SnippetFingerprint `json:"snippet,omitempty"`
}

type SnippetFingerprint struct {
	Range string `json:"range,omitempty"`
	Value string `json:"value,omitempty"`
}
