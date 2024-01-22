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

// Language is the language of source code
type Language string

const (
	LanguageUnknown    Language = ""
	LanguageCPP        Language = "c++"
	LanguageDart       Language = "dart"
	LanguageDotnet     Language = "dotnet"
	LanguageElixir     Language = "elixir"
	LanguageErlang     Language = "erlang"
	LanguageGo         Language = "go"
	LanguageHaskell    Language = "haskell"
	LanguageJava       Language = "maven"
	LanguageJavaScript Language = "javascript"
	LanguagePHP        Language = "php"
	LanguagePython     Language = "python"
	LanguageRuby       Language = "ruby"
	LanguageRust       Language = "rust"
	LanguageSwift      Language = "swift"
)

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

type SnippetFingerprint struct {
	Range string `json:"range,omitempty"`
	Value string `json:"value,omitempty"`
}
type FingerprintValue struct {
	File    string               `json:"file,omitempty"`
	Snippet []SnippetFingerprint `json:"snippet,omitempty"`
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
