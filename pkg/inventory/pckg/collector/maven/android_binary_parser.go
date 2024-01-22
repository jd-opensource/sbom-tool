// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"archive/zip"
	"errors"
	"io"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/ziputil"
)

// AndroidBinaryParser is a parser for apk file.
type AndroidBinaryParser struct{}

// NewAndroidBinaryParser returns a new CartFileParser
func NewAndroidBinaryParser() *AndroidBinaryParser {
	return &AndroidBinaryParser{}
}

func (p *AndroidBinaryParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.apk", "*.aab"}}
}

func (p *AndroidBinaryParser) Parse(path string) ([]model.Package, error) {
	prefix := ""
	if strings.HasSuffix(path, ".apk") {
		prefix = "META-INF/"
	} else if strings.HasSuffix(path, ".aab") {
		prefix = "base/root/META-INF/"
	} else {
		return nil, errors.New("only support apk and aab file")
	}

	var pkgs []model.Package
	err := ziputil.TraverseFilesInZip(path, func(file *zip.File) error {
		// for apk: META-INF/androidx.core_core.version
		// for aab: base/root/META-INF/androidx.core_core.version
		if strings.HasPrefix(file.Name, prefix) {
			name := file.Name[len(prefix):]
			if !strings.Contains(name, "/") && strings.HasSuffix(name, ".version") {
				pkg, err := parsePackageFromVersionFile(name, file, path)
				if err != nil {
					log.Warnf("parse version file error: %s", err.Error())
					return err
				}
				if pkg != nil {
					pkgs = append(pkgs, *pkg)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Errorf("parse file error: %s", err.Error())
	}
	return pkgs, nil
}

func parsePackageFromVersionFile(name string, file *zip.File, sourcePath string) (*model.Package, error) {
	name = name[0 : len(name)-8]
	var groupID, artifactID, version string
	items := strings.Split(name, "_")
	if len(items) == 2 {
		groupID = items[0]
		artifactID = items[1]
	} else {
		artifactID = name
	}
	r, err := file.Open()
	if err != nil {
		log.Warnf("open file from apk error: %s", err.Error())
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		log.Warnf("read file from apk error: %s", err.Error())
		return nil, err
	}
	content := strings.TrimSpace(string(data))
	// content is a version of semver format,
	if content != "" && !strings.Contains(content, " ") && content[0] >= 49 && content[0] <= 58 {
		version = content
	}
	pkg := newPackage(groupID, artifactID, version, sourcePath)
	return pkg, nil
}
