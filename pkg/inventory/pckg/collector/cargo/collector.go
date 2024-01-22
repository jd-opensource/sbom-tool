// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cargo

import (
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

type Collector struct {
	collector.BaseCollector
}

var parsers []collector.FileParser

func init() {
	parsers = append(parsers, NewCargoFileParser())
	parsers = append(parsers, NewCargoTomlFileParser())
	parsers = append(parsers, NewRustBinaryParser())
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
	tomlReq, lockReq := pickRequest(reqs)

	if lockReq != nil {
		pkgs, err = lockReq.Parser.Parse(lockReq.File.FullName())
		return
	}

	if tomlReq != nil && lockReq == nil {
		pkgs, err = tomlReq.Parser.Parse(tomlReq.File.FullName())
	}

	return pkgs, err
}

func pickRequest(reqs []collector.Request) (tomlReq *collector.Request, lockReq *collector.Request) {
	var ok bool
	for i, req := range reqs {
		if _, ok = req.Parser.(*RustCargoTomlFileParser); ok {
			tomlReq = &reqs[i]
		} else if _, ok = req.Parser.(*RustCargoFileParser); ok {
			lockReq = &reqs[i]
		}
	}
	return
}
