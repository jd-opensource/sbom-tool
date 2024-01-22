// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ziputil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"

	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// ZipReadCloser zip Reader and Closer
type ZipReadCloser struct {
	*zip.Reader
	io.Closer
}

// OpenZip provides a ZipReadCloser for the given filepath.
func OpenZip(path string) (*ZipReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of file: %w", err)
	}

	offset := 0
	size := fi.Size() - int64(offset)

	r, err := zip.NewReader(io.NewSectionReader(file, int64(offset), size), size)
	if err != nil {
		return nil, fmt.Errorf("unable to open zip file @ %q: %w", path, err)
	}

	return &ZipReadCloser{
		Reader: r,
		Closer: file,
	}, nil
}

func ReadFileContext(file *zip.File) string {
	context := ""
	f, err := file.Open()
	if err != nil {
		log.Errorf("open  file %s error,err:%s", file.Name, err.Error())
		return ""
	}
	if file.FileInfo().IsDir() {
		log.Errorf("open  file %s is dir error", file.Name)
		return ""
	}
	var buffer bytes.Buffer
	if err := SafeCopy(&buffer, f); err != nil {
		log.Errorf("open  file %s SafeCopy buffer error,err:%s", file.Name, err.Error())
		return ""
	}
	context = buffer.String()

	defer func() {
		err = f.Close()
		if err != nil {
			log.Errorf("unable to close  file %s,err:%s", file.Name, err.Error())
		}
	}()

	return context
}
