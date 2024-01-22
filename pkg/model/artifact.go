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

// FileType is the type of the file
type FileType string

const (
	FileTypeSource        FileType = "SOURCE"        // if the file is human-readable source code (.c, .html, etc.);
	FileTypeBinary        FileType = "BINARY"        //  if the file is a compiled object, target image or binary executable (.o, .a, etc.);
	FileTypeArchive       FileType = "ARCHIVE"       //  if the file represents an archive (.tar, .jar, etc.);
	FileTypeApplication   FileType = "APPLICATION"   //  if the file is associated with a specific application type (MIME type of application/*);
	FileTypeAudio         FileType = "AUDIO"         //  if the file is associated with an audio file (MIME type of audio/* , e.g. .mp3);
	FileTypeImage         FileType = "IMAGE"         //  if the file is associated with a picture image file (MIME type of image/*, e.g., .jpg, .gif);
	FileTypeText          FileType = "TEXT"          //  if the file is human-readable text file (MIME type of text/*);
	FileTypeVideo         FileType = "VIDEO"         //  if the file is associated with a video file type (MIME type of video/*);
	FileTypeDocumentation FileType = "DOCUMENTATION" //  if the file serves as documentation;
	FileTypeSPDX          FileType = "SPDX"          //  if the file is an SPDX document;
	FileTypeOther         FileType = "OTHER"         //  if the file doesn't fit into the above categories (generated artifacts, data files, etc.)
)

// Artifact represents the distribution artifact of the sbom
type Artifact struct {
	ID string `json:"id"`
	Package
	Build Build  `json:"build"`
	Files []File `json:"files"`
}

// Build represents the build information of the artifact
type Build struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	Builder  string `json:"builder"`
	Compiler string `json:"compiler"`
}

// File represents the file in the artifact
type File struct {
	Name      string         `json:"name"`
	Type      FileType       `json:"type"`
	Checksums []FileChecksum `json:"checksums"`
}
