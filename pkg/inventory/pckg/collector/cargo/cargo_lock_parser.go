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
	"fmt"
	"io"
	"os"

	"github.com/pelletier/go-toml"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

// RustCargoFileParser is a parser for Cargo.lock file
// see: https://doc.rust-lang.org/cargo/reference/manifest.html
//
//	https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html
type RustCargoFileParser struct {
}

// NewCargoFileParser returns a new RustCargoFileParser
func NewCargoFileParser() *RustCargoFileParser {
	return &RustCargoFileParser{}
}

type cargoLockFile struct {
	Packages []CargoPackageMetadata `toml:"package"`
}

func (m *RustCargoFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Cargo.lock"}}
}

func (m *RustCargoFileParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCargolockFile(f, filePath)
}

func parseCargolockFile(reader io.Reader, filePath string) ([]model.Package, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to load Cargo.lock for parsing: %w", err)
	}

	c := cargoLockFile{}
	err = tree.Unmarshal(&c)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Cargo.lock: %w", err)
	}

	var pkgs []model.Package

	var cargoPkgMap = make(map[string]CargoPackageMetadata)
	for _, cpm := range c.Packages {
		cargoPkgMap[cpm.Name] = cpm
	}

	for _, p := range c.Packages {
		pkgs = append(pkgs, NewPkgFromCargoMetadata(p, cargoPkgMap, filePath))
	}
	return pkgs, nil
}
