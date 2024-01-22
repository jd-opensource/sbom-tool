// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package archive

import (
	"path/filepath"
	"regexp"
	"strings"
)

type versionedFilename struct {
	raw     string
	name    string
	version string
}

var nameVersionFormat = regexp.MustCompile(`(?Ui)^(?P<pkgName>(?:[[:alpha:]][[:word:].]*(?:\.[[:alpha:]][[:word:].]*)*-?)+)(?:-(?P<pkgVersion>(\d.*|(build\d*.*)|(rc?\d+(?:^[[:alpha:]].*)?))))?$`)

func parseJavaArchiveFilename(raw string) versionedFilename {
	cleanedFileName := strings.TrimSuffix(filepath.Base(raw), filepath.Ext(raw))

	matches := nameVersionFormat.FindStringSubmatch(cleanedFileName)

	name := getMatchedValue(matches, nameVersionFormat.SubexpIndex("pkgName"))
	version := getMatchedValue(matches, nameVersionFormat.SubexpIndex("pkgVersion"))

	return versionedFilename{
		raw:     raw,
		name:    name,
		version: version,
	}
}

func getMatchedValue(matches []string, index int) string {
	if len(matches) < index+1 {
		return ""
	}
	return matches[index]
}
