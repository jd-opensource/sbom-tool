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
	"strings"

	"github.com/pelletier/go-toml"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

// RustCargoTomlFileParser is a parser for Cargo.toml file
// see: https://doc.rust-lang.org/cargo/reference/manifest.html
//
//	https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html
type RustCargoTomlFileParser struct {
}

// NewCargoTomlFileParser returns a new RustCargoTomlFileParser
func NewCargoTomlFileParser() *RustCargoTomlFileParser {
	return &RustCargoTomlFileParser{}
}

func (m *RustCargoTomlFileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Cargo.toml"}}
}

func (m *RustCargoTomlFileParser) Parse(filePath string) ([]model.Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCargoTomlFile(f, filePath)
}

func parseCargoTomlFile(reader io.Reader, filePath string) ([]model.Package, error) {
	pkgs := make([]model.Package, 0)

	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to load Cargo.lock for parsing: %w", err)
	}

	if tree.Values()["dependencies"] == nil {
		return pkgs, fmt.Errorf("missing dependencies node: %w", err)
	}

	if tree.Values()["package"] == nil {
		return pkgs, fmt.Errorf("missing package node: %w", err)
	}

	mainPackage, err := parseMainPackage(tree, filePath)
	if err != nil {
		return nil, fmt.Errorf("parse main package from toml fail: %w", err)
	}

	pkgs = append(pkgs, *mainPackage)

	dependencies := tree.Values()["dependencies"]
	if _, ok := dependencies.(*toml.Tree); !ok {
		return pkgs, nil
	}

	tomlTree := dependencies.(*toml.Tree)

	if tomlTree == nil || tomlTree.Values() == nil {
		return pkgs, nil
	}

	waitParsePkgMap := tomlTree.Values()
	for pkgName, pkg := range waitParsePkgMap {
		version := ""

		if _, ok := pkg.(*toml.Tree); ok {
			tomlTree := pkg.(*toml.Tree)
			valueMap := tomlTree.Values()
			v := valueMap["version"]

			if v == nil {
				version = ""
			}

			if valueMap["rev"] != nil {
				v = valueMap["rev"]
			}

			if _, ok := v.(*toml.PubTOMLValue); ok {
				pubTOMLValue := v.(*toml.PubTOMLValue)
				value := pubTOMLValue.Value()

				if _, ok := value.(string); ok {
					version = value.(string)
				}
			}
		}

		if _, ok := pkg.(*toml.PubTOMLValue); ok {
			pubTOMLValue := pkg.(*toml.PubTOMLValue)
			value := pubTOMLValue.Value()
			if _, ok := value.(string); ok {
				version = value.(string)
			}
		}
		pkgVersion := removeSpecialCharacters(version)
		p := newPackage(pkgName, pkgVersion, filePath)
		pkgs = append(pkgs, *p)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func removeSpecialCharacters(input string) string {
	// 定义需要去除的特殊字符
	specialChars := "~^*"
	// 将特殊字符替换为空字符串
	result := strings.Map(func(r rune) rune {
		if strings.ContainsRune(specialChars, r) {
			return -1
		}
		return r
	}, input)
	return result
}

func parseMainPackage(tree *toml.Tree, filePath string) (*model.Package, error) {
	mainPackageTreeValue := tree.Values()["package"]
	if _, ok := mainPackageTreeValue.(*toml.Tree); !ok {
		return nil, fmt.Errorf("missing package node when parsing toml file")
	}
	mainPackageTomlTree := mainPackageTreeValue.(*toml.Tree)
	tomlTreeValues := mainPackageTomlTree.Values()

	mainPackageName := ""
	mainPackageVersion := ""
	for mainPkgDesKey, mainPkgDesValue := range tomlTreeValues {
		if mainPkgDesKey == "name" {
			if _, ok := mainPkgDesValue.(*toml.PubTOMLValue); ok {
				pubTOMLValue := mainPkgDesValue.(*toml.PubTOMLValue)
				value := pubTOMLValue.Value()
				if _, ok := value.(string); ok {
					mainPackageName = value.(string)
				}
			}
			continue
		}

		if mainPkgDesKey == "version" {
			if _, ok := mainPkgDesValue.(*toml.PubTOMLValue); ok {
				ss := mainPkgDesValue.(*toml.PubTOMLValue)
				value := ss.Value()
				if _, ok := value.(string); ok {
					mainPackageVersion = removeSpecialCharacters(value.(string))
				}
			}
			continue
		}
	}
	pkg := newPackage(mainPackageName, mainPackageVersion, filePath)
	return pkg, nil
}
