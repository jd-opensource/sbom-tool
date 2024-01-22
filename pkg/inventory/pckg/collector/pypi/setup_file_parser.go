// Copyright 2023 Jingdong Technology Information Technology Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pypi

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
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var dependency_package_re = regexp.MustCompile(
	`['"][\W-]?([\w-]+\W?==\W?[\w.]*)`)

// SetUpParser is a parser for setup.py file
// see: https://docs.python.org/3/distutils/setupscript.html
type SetUpParser struct{}

func NewSetUpParser() *SetUpParser {
	return &SetUpParser{}
}

func (m *SetUpParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"setup.py"}}
}

func (m *SetUpParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python SetUpParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return parseSetUpFile(f, filePath)
}

func parseSetUpFile(reader io.Reader, sourcePath string) ([]model.Package, error) {

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

		for _, m := range dependency_package_re.FindAllString(lineText, -1) {
			strArr := strings.Split(m, "==")
			if len(strArr) != 2 {
				continue
			}

			packageName := strings.TrimSpace(strArr[0])
			packageName = strings.Trim(packageName, "\"'")
			packageName = strings.TrimSpace(packageName)

			packageVersion := strings.TrimSpace(strArr[1])
			packageVersion = strings.Trim(packageVersion, "\"'")
			packageVersion = strings.TrimSpace(packageVersion)

			if packageName == "" {
				continue
			}

			if strings.Contains(packageName, `%`) || strings.Contains(packageVersion, `%`) {
				continue
			}
			pkg := newPackage(packageName, packageVersion, sourcePath)
			pkgs = append(pkgs, *pkg)
		}

	}
}
