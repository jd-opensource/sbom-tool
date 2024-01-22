// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conda

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

var (
	dependency_package_re = regexp.MustCompile(
		`(.+)==?([0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+)(=.+)?`)
	pkgName    = ""
	pkgVersion = ""
)

// CondaFileParser is a parser for config of condo project.
// see: https://docs.conda.io/projects/conda/en/stable/dev-guide/api/conda_env/specs/yaml_file/index.html
type CondaFileParser struct{}

func NewCondaFileParser() *CondaFileParser {
	return &CondaFileParser{}
}

func (m *CondaFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"environment.yml", "environment.yaml", "package-list.txt"}}
}

func (m *CondaFileParser) Parse(filePath string) ([]model.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	return parseCondaFile(file, filePath)
}

func parseCondaFile(reader io.Reader, filePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)

	r := bufio.NewReader(reader)
	for {
		lineText, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err) && lineText == "":
			return pkgs, nil
		case err != nil && err != io.EOF:
			return nil, fmt.Errorf("failed to parse conda file: %w", err)
		}
		lineText = strings.TrimSpace(lineText)

		if lineText == "" {
			continue
		}

		if strings.HasPrefix(lineText, "#") {
			continue
		}

		if dependency_package_re.MatchString(lineText) {
			pkgName, pkgVersion = condaPkgStrParse(lineText)
			if pkgName == "" {
				continue
			}

			pkg := newPackage(pkgName, pkgVersion, filePath)
			pkgs = append(pkgs, *pkg)
		}

	}
}

func condaPkgStrParse(pkgInfoStr string) (string, string) {
	pkgInfoList := strings.Split(pkgInfoStr, "=")
	if len(pkgInfoList) < 2 {
		return pkgName, pkgVersion
	}

	pkgName = strings.TrimSpace(pkgInfoList[0])
	pkgName = strings.ReplaceAll(pkgName, "=", "")
	pkgName = strings.ReplaceAll(pkgName, "- ", "")

	if pkgInfoList[1] == "" {
		//dlib==19.19.0
		pkgVersion = strings.TrimSpace(pkgInfoList[2])
	} else {
		//dlib=19.19.0=py37
		pkgVersion = strings.TrimSpace(pkgInfoList[1])
	}
	return pkgName, pkgVersion
}
