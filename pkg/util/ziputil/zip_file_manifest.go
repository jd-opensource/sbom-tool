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
	"fmt"
	"os"
	"sort"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// FileManifest is a collection of paths and their file metadata.
type FileManifest map[string]os.FileInfo

// ResolveFileManifest creates and returns a new ZipFileManifest
// populated with path and metadata from the given zip archive path.
func ResolveFileManifest(path string) (FileManifest, error) {
	zipRc, err := OpenZip(path)
	manifest := make(FileManifest)
	if err != nil {
		return manifest, fmt.Errorf("unable to open zip archive (%s): %w", path, err)
	}
	defer func() {
		err = zipRc.Close()
		if err != nil {
			log.Warnf("unable to close zip archive (%s): %+v", path, err)
		}
	}()

	for _, file := range zipRc.Reader.File {
		manifest.Add(file.Name, file.FileInfo())
	}
	return manifest, nil
}

func (f FileManifest) Add(path string, info os.FileInfo) {
	f[path] = info
}

func (f FileManifest) GlobMatch(patterns ...string) []string {
	var matches []string

	for _, pattern := range patterns {
		for path := range f {
			normalizedPath := normalizePath(path)

			if GlobMatch(pattern, normalizedPath) {
				matches = append(matches, path)
			}
		}
	}

	sort.Strings(matches)

	return matches
}

func normalizePath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}

	return path
}

func GlobMatch(pattern, path string) bool {
	pIndex := 0
	nIndex := 0
	nextPIndex := 0
	nextNIndex := 0
	for pIndex < len(pattern) || nIndex < len(path) {
		if pIndex < len(pattern) {
			c := pattern[pIndex]
			switch c {
			default: // ordinary character
				if nIndex < len(path) && path[nIndex] == c {
					pIndex++
					nIndex++

					continue
				}
			case '?': // single-character wildcard
				if nIndex < len(path) {
					pIndex++
					nIndex++

					continue
				}
			case '*': // zero-or-more-character wildcard
				nextPIndex = pIndex
				nextNIndex = nIndex + 1
				pIndex++

				continue
			}
		}
		if 0 < nextNIndex && nextNIndex <= len(path) {
			pIndex = nextPIndex
			nIndex = nextNIndex
			continue
		}
		return false
	}
	return true
}
