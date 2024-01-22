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

	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// GetTextFromZip get content by path from given archive file
func GetTextFromZip(zipPath string, path string) (string, error) {
	lines, err := GetLinesFromZip(zipPath, path)
	return lines[path], err
}

// GetLinesFromZip extracts select paths for the given archive and returns a set of string contents for each path.
func GetLinesFromZip(zipPath string, paths ...string) (map[string]string, error) {
	lines := make(map[string]string)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return lines, nil
	}

	visitor := func(file *zip.File) error {
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("error occurs when read file=%q from zip=%q: %w", file.Name, zipPath, err)
		}

		if file.FileInfo().IsDir() {
			return fmt.Errorf("can not be directory, only files: %s", file.Name)
		}

		var buffer bytes.Buffer
		if err := SafeCopy(&buffer, rc); err != nil {
			return fmt.Errorf("error occurs when copy source=%q for zip=%q: %w", file.Name, zipPath, err)
		}

		lines[file.Name] = buffer.String()

		err = rc.Close()
		if err != nil {
			return fmt.Errorf("error occurs when close source file=%q from zip=%q: %w", file.Name, zipPath, err)
		}
		return nil
	}

	return lines, TraverseFilesInZip(zipPath, visitor, paths...)
}

type zipTraversalRequest map[string]struct{}

func newZipTraverseRequest(paths ...string) zipTraversalRequest {
	results := make(zipTraversalRequest)
	for _, p := range paths {
		results[p] = struct{}{}
	}
	return results
}

// TraverseFilesInZip enumerates all paths stored within a zip archive using the visitor pattern.
func TraverseFilesInZip(zipPath string, visitor func(*zip.File) error, targetPaths ...string) error {
	request := newZipTraverseRequest(targetPaths...)

	rc, err := OpenZip(zipPath)
	if err != nil {
		return fmt.Errorf("unable to open zip archive (%s): %w", zipPath, err)
	}
	defer func() {
		err = rc.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %+v", zipPath, err)
		}
	}()

	for _, item := range rc.Reader.File {
		// if no paths are given then assume that all files should be traversed
		if len(targetPaths) > 0 {
			if _, ok := request[item.Name]; !ok {
				// this file path is not of interest
				continue
			}
		}

		if err = visitor(item); err != nil {
			return err
		}
	}
	return nil
}
