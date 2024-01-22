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
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// FileParser  specify a FileMatcher to match files, and parse the recognizable files to discover packages
type FileParser interface {
	// Matcher return the specified file parser
	Matcher() FileMatcher
	// Parse the given path and return discovered packages
	Parse(path string) (pkgs []model.Package, err error)
}

// MainPkgParser parse a file and generate main package
type MainPkgParser interface {
	ParseMain(path string) (pkg *model.Package, err error)
}

// Request represents a file and parser pair, and the parser can recognize and parse the file
type Request struct {
	File   File
	Parser FileParser
}
