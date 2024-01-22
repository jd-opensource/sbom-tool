// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package npm

import (
	"os"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

type Collector struct {
	collector.BaseCollector
}

var parsers []collector.FileParser

func init() {
	parsers = append(parsers, NewPackageJSONParser())
	parsers = append(parsers, NewPackageLockJSONParser())
	parsers = append(parsers, NewYarnLockParser())
	parsers = append(parsers, NewPnpmLockParser())
}

func NewCollector() *Collector {
	c := Collector{}
	c.Name = Name()
	c.PurlType = PkgType()
	c.Parsers = parsers
	return &c
}

func (c *Collector) Collect() ([]model.Package, error) {
	// 根据目录分组
	dirRequests := make(map[string][]collector.Request)
	for _, req := range c.Requests {
		dirRequests[req.File.Dir()] = append(dirRequests[req.File.Dir()], req)
	}

	depTree := collector.NewDependencyTree()
	for _, reqs := range dirRequests {
		mainReq, subReqs := pickRequest(reqs)
		var mainPkg *model.Package
		var subPkgs []model.Package

		if mainReq != nil {
			mainParser := mainReq.Parser.(collector.MainPkgParser)
			var err error
			mainPkg, err = mainParser.ParseMain(mainReq.File.FullName())
			if err != nil {
				log.Warnf("parse main package error: %s", err.Error())
			}
		}

		for _, req := range subReqs {
			if _, ok := req.Parser.(collector.MainPkgParser); !ok {
				ps, err := req.Parser.Parse(req.File.FullName())
				if err != nil {
					log.Warnf("parse sub package error: %s", err.Error())
				}
				subPkgs = append(subPkgs, ps...)
			}
		}
		if len(subPkgs) == 0 {
			ps, err := mainReq.Parser.Parse(mainReq.File.FullName())
			if err != nil {
				log.Warnf("parse sub package error: %s", err.Error())
			}
			subPkgs = append(subPkgs, ps...)
		}
		if mainPkg != nil && mainPkg.Name != "" {
			depTree.AddPackage(mainPkg)
			for _, pkg := range subPkgs {
				p := pkg
				depTree.AddPackage(&p)
				depTree.AddDependency(mainPkg.PURL, pkg.PURL)
			}
		} else {
			for _, pkg := range subPkgs {
				p := pkg
				depTree.AddPackage(&p)
				depTree.AddPackage(&pkg)
			}
		}
	}
	pkgs := depTree.ToList()
	pkgs = collector.OrganizePackage(pkgs)
	return pkgs, nil
}

func pickRequest(reqs []collector.Request) (*collector.Request, []*collector.Request) {
	if len(reqs) == 0 {
		return nil, nil
	}
	var ok bool
	var mainReq *collector.Request
	var latestReq *collector.Request
	var subReqs []*collector.Request
	for i, req := range reqs {
		if _, ok = req.Parser.(collector.MainPkgParser); ok {
			mainReq = &reqs[i]
		} else {
			r := req
			subReqs = append(subReqs, &r)
			if latestReq == nil {
				latestReq = &reqs[i]
			} else if req.File.Stat() != nil && latestReq.File.Stat() != nil &&
				req.File.Stat().ModTime().After(latestReq.File.Stat().ModTime()) {
				// choose the most recent one
				latestReq = &reqs[i]
			}
		}
	}
	npmLock := os.Getenv("SBOMTOOL-NPM-LOCK")
	switch npmLock {
	case "all":
		return mainReq, subReqs
	case "latest":
		return mainReq, []*collector.Request{latestReq}
	default:
		return mainReq, subReqs
	}
}
