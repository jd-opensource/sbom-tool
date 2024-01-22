// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dylib

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/ziputil"
)

// IPAParser is a parser for bower.json file.
type IPAParser struct{}

// NewIPAParser returns a new CartFileParser
func NewIPAParser() *IPAParser {
	return &IPAParser{}
}

func (p *IPAParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.ipa"}}
}

func (p *IPAParser) Parse(path string) ([]model.Package, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()
	workDir := filepath.Join(os.TempDir(), filepath.Base(path))
	err = os.MkdirAll(workDir, 0777)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(workDir)
	}()
	var pkgs []model.Package
	for i := 0; i < len(reader.File); i++ {
		file := reader.File[i]
		name := file.Name
		if strings.HasPrefix(name, "Payload/") {
			name = name[8:]
			items := strings.SplitN(name, "/", 2)
			if len(items) == 2 && len(items[0]) > 4 && strings.HasSuffix(items[0], ".app") {
				name = items[1]
				if strings.HasPrefix(name, "Frameworks/") {
					name = name[11:]
					if strings.HasSuffix(name, ".dylib") {
						// Frameworks/libswift_Concurrency.dylib
						p, e := parseDylibFile(file, workDir, path)
						if e != nil {
							log.Warnf("parse dylib file error: %s", e.Error())
							return nil, err
						}
						pkgs = append(pkgs, p...)
					} else if strings.Contains(name, ".framework/") {
						fileName := filepath.Base(name)
						// Frameworks/TestFlightServices.framework/TestFlightServices
						if name == fileName+".framework/"+fileName {
							p, e := parseDylibFile(file, workDir, path)
							if e != nil {
								log.Warnf("parse dylib file error: %s", e.Error())
								return nil, err
							}
							pkgs = append(pkgs, p...)
						}
					}
				}
			}
		}
	}
	pkgs = collector.OrganizePackage(pkgs)
	return pkgs, nil
}

func parseDylibFile(file *zip.File, workDir string, sourcePath string) ([]model.Package, error) {
	reader, err := file.Open()
	if err != nil {
		log.Warnf("open file error: " + err.Error())
		return nil, err
	}
	tempFile := filepath.Join(workDir, filepath.Base(file.Name))
	writer, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = writer.Close()
		_ = os.Remove(tempFile)
	}()
	err = ziputil.SafeCopy(writer, reader)
	if err != nil {
		return nil, err
	}
	fatFile, err := macho.OpenFat(tempFile)
	if err != nil {
		if errors.Is(err, macho.ErrNotFat) {
			machoFile, err := macho.Open(tempFile)
			if err != nil {
				return nil, err
			}
			return parseMachoFile(machoFile, sourcePath)
		} else {
			return nil, err
		}
	}
	pkgs := make([]model.Package, 0)
	for i := 0; i < len(fatFile.Arches); i++ {
		arch := fatFile.Arches[i]
		p, e := parseMachoFile(arch.File, sourcePath)
		if e != nil {
			log.Warnf("parse macho file error: ", e.Error())
			continue
		}
		pkgs = append(pkgs, p...)
	}
	return pkgs, nil
}

func parseMachoFile(file *macho.File, sourcePath string) ([]model.Package, error) {
	if file == nil {
		return nil, errors.New("macho file is nil")
	}
	pkgs := make([]model.Package, 0)
	for i := 0; i < len(file.Loads); i++ {
		load := file.Loads[i]
		// LC_ID_DYLIB                 @rpath/libswift_Concurrency.dylib (5.7.2)
		// LC_LOAD_DYLIB               /usr/lib/libobjc.A.dylib (228.0)
		// LC_LOAD_DYLIB               /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (1949.0)
		if load.Command() == types.LC_ID_DYLIB || load.Command() == types.LC_LOAD_DYLIB {
			nameVer := load.String()
			p := parseDylibLine(nameVer, sourcePath)
			pkgs = append(pkgs, *p)
		}
	}
	return pkgs, nil
}

func parseDylibLine(line string, sourcePath string) *model.Package {
	items := strings.Split(line, " ")
	if len(items) != 2 {
		return nil
	}
	path := strings.TrimSpace(items[0])
	version := strings.Trim(items[1], " ()")
	name := filepath.Base(path)
	if strings.HasSuffix(name, ".dylib") {
		name = name[0 : len(name)-6]
	}
	p := newPackage(name, version, sourcePath)
	return &p
}
