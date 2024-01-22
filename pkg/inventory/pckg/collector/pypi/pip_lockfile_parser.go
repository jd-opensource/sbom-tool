// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pypi

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

type PipLockInfo struct {
	Default map[string]PipLockDependency `json:"default"`
}

type PipLockDependency struct {
	Version string `json:"version"`
}

// PipLockParser is a parser for Pipfile.lock file
// see: https://pipenv.pypa.io/en/latest/pipfile/
type PipLockParser struct{}

func NewPipLockParser() *PipLockParser {
	return &PipLockParser{}
}

func (m *PipLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Pipfile.lock"}}
}

func (m *PipLockParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python PipLockParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parsePipLockFile(f, filePath)
}

func parsePipLockFile(reader io.Reader, sourcePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	var pipLockInfo PipLockInfo
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&pipLockInfo)
	if err != nil {
		log.Errorf("Failed to decode JSON PipLockFile: %s", err.Error())
	}

	for name, pipLockDependency := range pipLockInfo.Default {
		packageName := strings.TrimSpace(name)
		packageVersion := strings.ReplaceAll(pipLockDependency.Version, "=", "")
		packageVersion = strings.TrimSpace(packageVersion)
		if packageName == "" {
			continue
		}

		pkg := newPackage(packageName, packageVersion, sourcePath)
		pkgs = append(pkgs, *pkg)
	}

	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}
