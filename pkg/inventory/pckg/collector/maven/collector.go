// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

type Collector struct {
	collector.BaseCollector
}

var parsers []collector.FileParser

func init() {
	parsers = append(parsers, NewArchiveParser())
	parsers = append(parsers, NewPOMXMLParser())
	parsers = append(parsers, NewJavaGradleFileParser())
	parsers = append(parsers, NewDependencyTreeParser())
	parsers = append(parsers, NewGradleDependencyTreeParser())
	parsers = append(parsers, NewAndroidBinaryParser())
}

func NewCollector() *Collector {
	c := Collector{}
	c.Name = Name()
	c.PurlType = PkgType()
	c.Parsers = parsers
	return &c
}

func (c *Collector) Collect() (pkgs []model.Package, err error) {
	reqs := c.Requests
	hasDependencyTreeReq := pickRequest(reqs)

	if hasDependencyTreeReq {
		//Use only DependencyTreeParser if maven-dependency-tree.txt file is included
		for _, request := range c.Requests {
			if _, ok := request.Parser.(*DependencyTreeParser); ok {
				items, _ := request.Parser.Parse(request.File.FullName())
				pkgs = append(pkgs, items...)
			} else {
				continue
			}
		}
	} else {
		for _, request := range c.Requests {
			items, _ := request.Parser.Parse(request.File.FullName())
			pkgs = append(pkgs, items...)
		}
	}

	// remove invalid packages
	pkgs = util.SliceFilter(pkgs, func(pkg model.Package) bool {
		if collector.StrictMode() {
			return pkg.Name != "" && strings.Contains(pkg.Name, "/")
		} else {
			return pkg.Name != ""
		}
	})

	// remove duplicate packages
	pkgs = collector.OrganizePackage(pkgs)

	return pkgs, nil
}

func pickRequest(reqs []collector.Request) bool {
	var ok bool
	for _, req := range reqs {
		if _, ok = req.Parser.(*DependencyTreeParser); ok {
			return true
		}
	}
	return false
}
