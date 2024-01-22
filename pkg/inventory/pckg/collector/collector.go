// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package collector

import (
	"os"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

var strictMode bool

func init() {
	val := os.Getenv("SBOM_STRICT_MODE")
	strictMode = val == "true" || val == "1"
}

// Collector contains a group of FileParsers, and define common method among the FileParsers
type Collector interface {
	// GetName uniquely describes a Collector
	GetName() string
	// GetPurlType return a string value according to the package url spec. For details,
	// ref https://github.com/package-url/purl-spec
	GetPurlType() string
	// GetParsers return inner FileParsers
	GetParsers() []FileParser
	// TryToAccept try to match the given file using inner FileParsers respectively, accept the file if matched
	TryToAccept(file File)
	// GetRequests return requests generated at TryToAccept phase
	GetRequests() []Request
	// Collect analyze the accepted files and return discovered packages
	Collect() (pkgs []model.Package, err error)
}

// BaseCollector provide common properties and behaviors inherited by other collectors
type BaseCollector struct {
	Name     string
	PurlType string
	Parsers  []FileParser
	Requests []Request
}

func (c *BaseCollector) GetName() string {
	return c.Name
}

func (c *BaseCollector) GetPurlType() string {
	return c.PurlType
}

func (c *BaseCollector) GetParsers() []FileParser {
	return c.Parsers
}

func (c *BaseCollector) GetRequests() []Request {
	return c.Requests
}

func (c *BaseCollector) TryToAccept(file File) {
	for _, parser := range c.Parsers {
		if parser.Matcher().Match(file) {
			request := Request{File: file, Parser: parser}
			c.Requests = append(c.Requests, request)
			return
		}
	}
}

func (c *BaseCollector) Collect() ([]model.Package, error) {
	pkgs := make([]model.Package, 0)
	for _, request := range c.Requests {
		items, _ := request.Parser.Parse(request.File.FullName())
		pkgs = append(pkgs, items...)
	}
	// remove invalid packages
	pkgs = util.SliceFilter(pkgs, func(pkg model.Package) bool {
		return pkg.Name != ""
	})
	// remove duplicate packages
	pkgs = OrganizePackage(pkgs)
	// sort packages by PURL
	pkgs = SortPackage(pkgs)
	return pkgs, nil
}

func acquirePackageURL(purlType, name, version string) string {
	return packageurl.NewPackageURL(
		purlType,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}

// SortPackage sorts packages by PURL
func SortPackage(pkgs []model.Package) []model.Package {
	for i := 0; i < len(pkgs); i++ {
		sort.Strings(pkgs[i].Dependencies)
	}
	return util.SliceSort(pkgs, func(p1, p2 model.Package) bool {
		return strings.Compare(p1.PURL, p2.PURL) <= -1
	})
}

// StrictMode is for check package
func StrictMode() bool {
	return strictMode
}

// OrganizePackage remove and merge duplicate packages
func OrganizePackage(pkgs []model.Package) []model.Package {
	pkgs = util.SliceFilter(pkgs, func(p model.Package) bool {
		if strictMode {
			return p.Name != "" && p.Version != ""
		} else {
			return p.Name != ""
		}
	})
	for i := 0; i < len(pkgs); i++ {
		if pkgs[i].PURL == "" {
			pkgs[i].PURL = acquirePackageURL(pkgs[i].Type, pkgs[i].Name, pkgs[i].Version)
		}
	}
	pkgs = util.SliceUniqueFunc(pkgs, func(p1 model.Package, p2 model.Package) model.Package {
		return *CombinePackage(&p1, &p2)
	}, func(p1 model.Package, p2 model.Package) bool {
		return (p1.Type == p2.Type && p1.Name == p2.Name && p1.Version == p2.Version) || // same type,name,version
			(p1.Type == p2.Type && p1.Name == p2.Name && (p1.Version == "" || p2.Version == "")) // same type,name and empty version
	})
	pkgs = SortPackage(pkgs)
	return pkgs
}

// CombinePackage combines two packages into one package
func CombinePackage(p1, p2 *model.Package) *model.Package {
	if p1.PURL != p2.PURL {
		if p1.Type != p2.Type || p1.Name != p2.Name {
			// different type and name, cannot combine
			return p1
		} else if p1.Version != "" && p2.Version != "" {
			// different and not empty version, cannot combine
			return p2
		} else if p1.Version != "" {
			// use not empty version
			return p1
		} else if p2.Version != "" {
			// use not empty version
			return p2
		}
	}

	if p1.Supplier == "" {
		p1.Supplier = p2.Supplier
	}
	p1.LicenseDeclared = util.SliceUnique(append(p1.LicenseDeclared, p2.LicenseDeclared...))
	p1.LicenseConcluded = util.SliceUnique(append(p1.LicenseConcluded, p2.LicenseConcluded...))
	p1.Dependencies = util.SliceUnique(append(p1.Dependencies, p2.Dependencies...))
	return p1
}

// EqualPackage checks two packages are equal
func EqualPackage(p1, p2 *model.Package) bool {
	return p1.Name == p2.Name &&
		p1.Version == p2.Version &&
		p1.Type == p2.Type &&
		p1.PURL == p2.PURL &&
		slices.Equal(p1.LicenseDeclared, p2.LicenseDeclared) &&
		slices.Equal(p1.LicenseConcluded, p2.LicenseConcluded) &&
		slices.Equal(p1.Dependencies, p2.Dependencies)
}
