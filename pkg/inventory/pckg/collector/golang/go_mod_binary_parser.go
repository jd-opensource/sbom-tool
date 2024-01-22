// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package golang

import (
	"debug/buildinfo"
	"io"
	"os"
	"runtime/debug"

	macho "github.com/anchore/go-macholibre"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

const devel = "(devel)"

var mimes = []string{
	"application/x-executable",
	"application/x-mach-binary",
	"application/x-elf",
	"application/x-sharedlib",
	"application/vnd.microsoft.portable-executable",
}

// GoBinaryParser is a parser for go binary file.
// see: https://pkg.go.dev/runtime/debug#BuildInfo
type GoBinaryParser struct{}

func NewGoBinaryParser() GoBinaryParser {
	return GoBinaryParser{}
}

func (GoBinaryParser) Matcher() collector.FileMatcher {
	return &collector.FileMimeMatcher{Mimes: mimes}
}

func (GoBinaryParser) Parse(path string) (pkgs []model.Package, err error) {
	log.Infof("parsed by GoBinaryParser: %w", path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgs, err = parseGoBinaryFile(f, path)
	pkgs = collector.SortPackage(pkgs)
	return pkgs, err
}

func parseGoBinaryFile(reader io.ReaderAt, sourcePath string) ([]model.Package, error) {
	mods := extractBuildInfo(reader)
	var pkgs []model.Package
	for _, mod := range mods {
		pkgs = append(pkgs, buildGoPkgInfo(mod, sourcePath)...)
	}
	return pkgs, nil
}

func buildGoPkgInfo(mod *debug.BuildInfo, sourcePath string) []model.Package {
	var pkgs []model.Package
	if mod == nil {
		return pkgs
	}

	var empty debug.Module
	if mod.Main == empty && mod.Path != "" {
		mod.Main = debug.Module{Path: mod.Path, Version: devel}
	}

	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}
		p := toPackage(dep, sourcePath)
		pkgs = append(pkgs, *p)
	}

	if mod.Main == empty {
		return pkgs
	}

	main := makeGoMainPackage(mod, sourcePath)
	pkgs = append(pkgs, *main)

	return pkgs
}
func makeGoMainPackage(mod *debug.BuildInfo, sourcePath string) *model.Package {
	dep := mod.Main
	if mod.Main.Replace != nil {
		dep = *mod.Main.Replace
	}
	main := newPackage(dep.Path, dep.Version, sourcePath)
	return main
}

// toPackage transform debug.Module to model.Package
func toPackage(dep *debug.Module, sourcePath string) *model.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}
	return newPackage(dep.Path, dep.Version, sourcePath)
}

// extractBuildInfo extract golang build info from file content
func extractBuildInfo(reader io.ReaderAt) []*debug.BuildInfo {
	readers, err := getReaders(reader)

	if err != nil {
		log.Errorf("open golang binary error: %v", err)
		return nil
	}

	var builds []*debug.BuildInfo
	for _, r := range readers {
		bi, err := buildinfo.Read(r)
		if err != nil {
			log.Warnf("read buildInfo error: %v", err)
			continue
		}
		if bi == nil {
			continue
		}
		builds = append(builds, bi)
	}

	return builds
}

// return multiple readers in case for multi-architecture binaries
func getReaders(reader io.ReaderAt) ([]io.ReaderAt, error) {
	if macho.IsUniversalMachoBinary(reader) {
		machoReaders, err := macho.ExtractReaders(reader)
		if err != nil {
			log.Debugf("extracting readers: %v", err)
			return nil, err
		}

		var readers []io.ReaderAt
		for _, e := range machoReaders {
			readers = append(readers, e.Reader)
		}

		return readers, nil
	}

	return []io.ReaderAt{reader}, nil
}
