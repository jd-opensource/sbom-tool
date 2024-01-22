// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package rpm

import (
	"fmt"
	"os"
	"strings"

	"github.com/cavaliergopher/rpm"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// RPMArchiveParser is a parser for rpm archive file
type RPMArchiveParser struct{}

// NewRPMArchiveParser returns a new RPMArchiveParser
func NewRPMArchiveParser() *RPMArchiveParser {
	return &RPMArchiveParser{}
}

func (p *RPMArchiveParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.rpm"}}
}

func (p *RPMArchiveParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open rpm file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	// Read the package headers
	rpmMeta, err := rpm.Read(file)
	if err != nil {
		log.Errorf("read rpm file error: %s", err.Error())
		return nil, err
	}
	depTree := collector.NewDependencyTree()
	mainPkg := newPackage(rpmMeta.Name(), versionRelease(rpmMeta.Version(), rpmMeta.Release()), path)
	license := strings.TrimSpace(rpmMeta.License())
	if license != "" {
		mainPkg.LicenseDeclared = []string{license}
	}
	depTree.AddPackage(&mainPkg)

	for _, req := range rpmMeta.Requires() {
		name := req.Name()
		version := versionRelease(req.Version(), req.Release())
		if strings.HasPrefix(name, "rpmlib(") {
			name = strings.Trim(name[6:], "()")
		} else if strings.HasPrefix(name, "lib") && strings.Contains(name, ".so") {
			// TODO: collect so(SharedObject) entry
			name = name[:strings.IndexRune(name, '(')]
			continue
		} else if util.SliceAny([]string{"(", ")", "%", "#", "/"}, func(s string) bool {
			return strings.Contains(name, s)
		}) {
			// contains bad char, skip it
			continue
		}

		pkg := newPackage(name, version, path)
		depTree.AddPackage(&pkg)
		depTree.AddDependency(mainPkg.PURL, pkg.PURL)
	}

	pkgs := depTree.ToList()
	return pkgs, nil
}

func versionRelease(version, release string) string {
	if version == "" && release == "" {
		return ""
	} else if release == "" {
		return version
	} else {
		return version + "-" + release
	}
}
