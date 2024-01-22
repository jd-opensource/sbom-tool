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
	"errors"
	"io"
	"os"

	"github.com/microsoft/go-rustaudit"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

var mimes = []string{
	"application/x-executable",
	"application/x-mach-binary",
	"application/x-elf",
	"application/x-sharedlib",
	"application/vnd.microsoft.portable-executable",
}

var (
	ErrUnrecognizedExe = errors.New("unrecognized executable format")
	ErrNonRustBinary   = errors.New("non Rust auditable binary")
)

// RustBinaryParser is a parser for rust binary file
// see: https://github.com/rust-secure-code/cargo-auditable
type RustBinaryParser struct{}

func NewRustBinaryParser() RustBinaryParser {
	return RustBinaryParser{}
}

func (RustBinaryParser) Matcher() collector.FileMatcher {
	return &collector.FileMimeMatcher{Mimes: mimes}
}

func (RustBinaryParser) Parse(path string) (pkgs []model.Package, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseRustBinaryFile(f, path)
}

func parseRustBinaryFile(reader io.ReaderAt, path string) ([]model.Package, error) {
	dependencyInfo, err := rustaudit.GetDependencyInfo(reader)
	if err != nil {
		return []model.Package{}, convertError(err)
	}

	pkgs := NewPackageFromBinaryDependency(dependencyInfo.Packages, path)
	return pkgs, nil
}

func convertError(err error) error {
	if err == rustaudit.ErrUnknownFileFormat {
		return ErrUnrecognizedExe
	}
	if err == rustaudit.ErrNoRustDepInfo {
		return ErrNonRustBinary
	}

	return err
}
