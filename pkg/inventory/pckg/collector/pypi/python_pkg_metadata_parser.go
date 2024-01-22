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
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/license"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

type PythonPkgMetadataInfo struct {
	Name    string `mapstruct:"Name"`
	Version string `mapstruct:"Version"`
	License string `mapstruct:"License"`
}

// PkgMetadataParser is a parser for python package metadata file
type PkgMetadataParser struct{}

func NewPkgMetadataParser() *PkgMetadataParser {
	return &PkgMetadataParser{}
}

func (m *PkgMetadataParser) Matcher() collector.FileMatcher {
	return &collector.FileRegexpMatcher{Regexps: []*regexp.Regexp{
		regexp.MustCompile("^.*dist-info/METADATA$"),
		regexp.MustCompile("^PKG-INFO$"),
	}}
}

func (m *PkgMetadataParser) Parse(filePath string) ([]model.Package, error) {
	log.Infof("python PkgMetadataParser file path: %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return ParseMetadataContent(f, filePath)
}

func ParseMetadataContent(reader io.Reader, sourcePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	metadatafields := make(map[string]string)
	pythonArtifactInfo := PythonPkgMetadataInfo{}
	metadataScanner := bufio.NewScanner(reader)

	for metadataScanner.Scan() {
		lineText := metadataScanner.Text()
		lineText = strings.TrimSpace(lineText)

		if lineText == "" {
			continue
		}

		if strings.Contains(lineText, ": ") {
			packageArr := strings.Split(lineText, ": ")
			key := strings.TrimSpace(packageArr[0])
			value := strings.TrimSpace(packageArr[1])
			metadatafields[key] = value
		}
	}

	err := mapstructure.Decode(metadatafields, &pythonArtifactInfo)
	if err != nil {
		return pkgs, fmt.Errorf("failed to parse parseMetadataContent mapstructure.Decode : %w", err)
	}
	licenseValue, _, _ := license.ParseLicenseName(pythonArtifactInfo.License)

	if pythonArtifactInfo.Name == "" {
		return pkgs, fmt.Errorf("parseMetadataContent pythonArtifactInfo.Name is null !")
	}

	pkgName := pythonArtifactInfo.Name
	pkgVersion := pythonArtifactInfo.Version

	pkg := newPackage(pkgName, pkgVersion, sourcePath)
	pkg.LicenseConcluded = []string{licenseValue}
	pkgs = append(pkgs, *pkg)

	return pkgs, nil
}
