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
	"regexp"

	"pault.ag/go/debian/control"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// DebControlFileParser is a parser for deb control file
// see: https://www.debian.org/doc/debian-policy/ch-controlfields.html
type DebControlFileParser struct{}

func NewDebControlFileParser() *DebControlFileParser {
	return &DebControlFileParser{}
}

func (p *DebControlFileParser) Matcher() collector.FileMatcher {
	return &collector.FileRegexpMatcher{Regexps: []*regexp.Regexp{
		regexp.MustCompile("debian/control$"),
	}}
}

func (p *DebControlFileParser) Parse(path string) ([]model.Package, error) {
	log.Infof("DebControlFileParser path:" + path)
	ret, err := control.ParseControlFile(path)
	if err != nil {
		log.Errorf("parse deb control error: %s", err.Error())
		return nil, err
	}
	if len(ret.Binaries) == 0 {
		log.Errorf("deb control package is null,return nil")
		return nil, err
	}

	depTree := collector.NewDependencyTree()

	for _, binary := range ret.Binaries {
		pkg := newPackage(binary.Package, "", path)
		depTree.AddPackage(&pkg)
		if len(binary.Depends.Relations) > 0 {
			debDependPkgParser(depTree, pkg, binary.Depends.Relations, path)
		}
	}
	pkgs := depTree.ToList()
	return pkgs, nil
}
