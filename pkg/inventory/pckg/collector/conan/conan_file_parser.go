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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// ConanFileParser is a parser for conanfile.txt file
// see: https://docs.conan.io/2/reference/conanfile_txt.html
type ConanFileParser struct{}

// NewConanFileParser returns a new ConanFileParser
func NewConanFileParser() *ConanFileParser {
	return &ConanFileParser{}
}

func (m *ConanFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"conanfile.txt"}}
}

func (m *ConanFileParser) Parse(filePath string) ([]model.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	license, err := getConanPkgLicense(filePath)
	if err != nil {
		log.Warnf("conanfile get license fail:" + err.Error())
	}

	return parseConanfile(file, filePath, license)
}

// parseConanfile parses conanfile.txt
func parseConanfile(reader io.Reader, filePath string, licenses map[string]string) ([]model.Package, error) {
	isRequires := false
	var pkgs []model.Package
	r := bufio.NewReader(reader)
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return pkgs, nil
		case err != nil:
			return nil, fmt.Errorf("failed to parse conanfile.txt file: %w", err)
		}

		switch {
		case strings.Contains(line, "[requires]"):
			isRequires = true
			continue
		case strings.ContainsAny(line, "[]#"):
			isRequires = false
			continue
		}

		if !isRequires {
			continue
		}

		ref := strings.TrimSpace(line)
		fields := strings.Split(ref, "/")

		var name, version string
		if len(fields) >= 2 {
			name = strings.TrimSpace(fields[0])
			version = strings.TrimSpace(fields[1])
		} else {
			name = strings.TrimSpace(fields[0])
		}
		if name == "" {
			continue
		}
		p := newPackage(name, version, filePath)
		p.LicenseConcluded = resolveLicense(name, version, licenses)
		pkgs = append(pkgs, *p)
	}
}
