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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// RequirementsParser is a parser for requirements.txt file
// see: https://pip.pypa.io/en/stable/reference/requirements-file-format/
type RequirementsParser struct{}

func NewRequirementsParser() *RequirementsParser {
	return &RequirementsParser{}
}

func (m *RequirementsParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"requirements*.txt"}}
}

func (m *RequirementsParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python RequirementsParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseRequirements(f, filePath)
}

func parseRequirements(reader io.Reader, sourcePath string) ([]model.Package, error) {

	pkgs := make([]model.Package, 0)
	r := bufio.NewReader(reader)
	for {
		lineText, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err) && lineText == "":
			return pkgs, nil
		case err != nil && err != io.EOF:
			return nil, fmt.Errorf("failed to parse *requirements*.txt file: %w", err)
		}
		lineText = strings.TrimSpace(lineText)

		if lineText == "" {
			continue
		}

		if lineText[0] == '#' || lineText[0] == '-' {
			continue
		}

		lineText = interceptTextByComment(lineText)
		lineText = interceptTextByInstallOptions(lineText)

		if !strings.Contains(lineText, "==") {
			continue
		}

		lineText = strings.ReplaceAll(lineText, `\`, "")

		packageArr := strings.Split(lineText, "==")
		if len(packageArr) < 2 {
			continue
		}

		packageName := strings.TrimSpace(packageArr[0])
		packageVersion := interceptTextByHash(packageArr[1])

		if packageName == "" {
			continue
		}

		pkg := newPackage(packageName, packageVersion, sourcePath)
		pkgs = append(pkgs, *pkg)

	}
}

func interceptTextByComment(str string) string {
	strArr := strings.Split(str, "#")
	return strings.TrimSpace(strArr[0])
}

func interceptTextByInstallOptions(str string) string {
	strArr := strings.Split(str, ";")
	return strings.TrimSpace(strArr[0])
}

func interceptTextByHash(str string) string {
	strArr := strings.Split(str, "--hash=")
	return strings.TrimSpace(strArr[0])
}
