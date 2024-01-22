// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package deb

import (
	"fmt"
	"io"
	"path/filepath"

	"pault.ag/go/debian/deb"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/license"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// debArchiveParser is a parser for deb archive file
type DEBArchiveParser struct{}

// NewDEBArchiveParser returns a new debArchiveParser
func NewDEBArchiveParser() *DEBArchiveParser {
	return &DEBArchiveParser{}
}

func (p *DEBArchiveParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.deb"}}
}

func (p *DEBArchiveParser) Parse(path string) ([]model.Package, error) {
	log.Infof("DEBArchiveParser path:" + path)
	debfileInfo, closer, err := deb.LoadFile(path)
	if err != nil {
		log.Errorf("parse deb binary error: %s", err.Error())
		return nil, err
	}
	defer closer()
	depTree := collector.NewDependencyTree()

	if &debfileInfo.Control == nil || debfileInfo.Control.Package == "" {
		log.Errorf("parse deb binary control.package name is null!")
		return nil, fmt.Errorf("parse deb binary control.package name is null!")
	}

	pkgname := debfileInfo.Control.Package
	pkgversion := ""
	if &debfileInfo.Control.Version != nil || debfileInfo.Control.Version.String() != "" {
		pkgversion = debfileInfo.Control.Version.String()
	}
	pkgLicenses := parseMainLicense(debfileInfo)
	pkg := newPackage(pkgname, pkgversion, path)
	pkg.LicenseDeclared = pkgLicenses
	pkg.Supplier = debfileInfo.Control.Maintainer
	depTree.AddPackage(&pkg)

	if &debfileInfo.Control.Depends != nil && len(debfileInfo.Control.Depends.Relations) > 0 {
		debDependPkgParser(depTree, pkg, debfileInfo.Control.Depends.Relations, path)
	}

	pkgs := depTree.ToList()
	return pkgs, err
}

func parseMainLicense(debfileInfo *deb.Deb) []string {
	licenseList := make([]string, 0)
	for {
		header, err := debfileInfo.Data.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Errorf("parse deb binary parseMainLicense error: %s", err.Error())
			continue
		}

		if filepath.Base(header.Name) == license.CopyrightFileName {
			licenseList = license.GetLicensesFromCopyright(debfileInfo.Data)
			break
		}
	}
	return licenseList
}
