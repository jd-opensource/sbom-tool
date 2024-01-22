// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package composer

import (
	"encoding/json"
	"io"
	"os"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

type PhpComposerLockInfo struct {
	Packages []PhpComposerLockMetadata `json:"packages"`
}

type PhpComposerLockMetadata struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license"`
}

type ComposerLockFileParser struct{}

func NewComposerLockFileParser() *ComposerLockFileParser {
	return &ComposerLockFileParser{}
}

func (m *ComposerLockFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"composer.lock"}}
}

func (m *ComposerLockFileParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseComposerLockFile(f, filePath)
}

func parseComposerLockFile(reader io.Reader, filePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	var composerLockInfo PhpComposerLockInfo
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&composerLockInfo)
	if err != nil {
		log.Errorf("Failed to decode JSON composerLockInfo: %s", err.Error())
		return pkgs, err
	}

	if len(composerLockInfo.Packages) == 0 {
		log.Warnf("composerLockInfo.Packages list is nil!")
		return pkgs, err
	}

	for _, info := range composerLockInfo.Packages {
		if info.Name == "" {
			continue
		}
		pkg := newPackage(info.Name, info.Version, filePath)

		pkgs = append(pkgs, *pkg)
	}

	return pkgs, nil
}
