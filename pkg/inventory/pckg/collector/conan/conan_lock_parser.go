// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

type conanLock struct {
	Version        string   `json:"version"`
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
}

// ConanLockParser is a parser for conan.lock
type ConanLockParser struct{}

// NewConanLockParser returns a new ConanLockParser
func NewConanLockParser() *ConanLockParser {
	return &ConanLockParser{}
}

func (m *ConanLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"conan.lock"}}
}

func (m *ConanLockParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseConanlock(f, filePath)
}

// parseConanlock parses conan.lock
func parseConanlock(reader io.Reader, filePath string) ([]model.Package, error) {
	var cl conanLock
	pkgs := make([]model.Package, 0)
	if err := json.NewDecoder(reader).Decode(&cl); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	for _, req := range cl.Requires {
		ref := strings.Split(req, "#")[0]
		fields := strings.Split(ref, "/")

		var name, version string
		if len(fields) >= 2 {
			name = fields[0]
			version = fields[1]
		} else {
			name = fields[0]
		}

		pkg := newPackage(name, version, filePath)
		pkgs = append(pkgs, *pkg)
	}

	return pkgs, nil
}
