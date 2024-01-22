// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cocoapods

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

// PodfileParser is a parser for Podfile file
// see: https://guides.cocoapods.org/syntax/podfile.html
type PodfileParser struct{}

// NewPodfileParser returns a new PodfileParser
func NewPodfileParser() *PodfileParser {
	return &PodfileParser{}
}

func (p *PodfileParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Podfile"}}
}

func (p *PodfileParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Podfile file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)
	pkgs := make([]model.Package, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "pod ") {
			items := strings.Split(line[4:], ",")
			name := strings.Trim(items[0], " '")
			version := ""
			if len(items) == 2 && !strings.Contains(items[1], "=>") {
				// pod 'Objection', '0.9'
				version = strings.Trim(items[1], " '")
			} else if len(items) >= 2 {
				for i := 1; i < len(items); i++ {
					param := strings.TrimSpace(items[i])
					if strings.HasPrefix(param, ":version") {
						segs := strings.SplitN(param, "=>", 2)
						if len(segs) > 1 {
							version = strings.Trim(segs[1], " '")
						}
					}
				}
			}
			pkg := newPackage(name, getVersion(version), path)
			pkgs = append(pkgs, *pkg)
		}
	}
	return pkgs, nil
}
