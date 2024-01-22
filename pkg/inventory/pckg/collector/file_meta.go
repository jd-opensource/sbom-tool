// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package collector

import (
	"os"
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
)

// File define file basic information
type File interface {
	FullName() string
	Dir() string
	FileName() string
	Mime() string
	Stat() os.FileInfo
}

// FileMeta contains file basic information
type FileMeta struct {
	fullName string
	fileName string
	dir      string
	mime     string
	stat     os.FileInfo
}

func NewFileMeta(path string) File {
	sf := FileMeta{}
	sf.fullName = path
	sf.fileName = filepath.Base(path)
	sf.dir = filepath.Dir(path)
	return &sf
}

func (s *FileMeta) FullName() string {
	return s.fullName
}

func (s *FileMeta) Dir() string {
	return s.dir
}

func (s *FileMeta) FileName() string {
	return s.fileName
}

func (s *FileMeta) Mime() string {
	if s.mime != "" {
		return s.mime
	}
	mtype, _ := mimetype.DetectFile(s.fullName)
	s.mime = mtype.String()
	return s.mime
}

func (s *FileMeta) Stat() os.FileInfo {
	if s.stat == nil {
		stat, _ := os.Stat(s.fullName)
		s.stat = stat
	}
	return s.stat
}
