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
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

// PodfileLockParser is a parser for Podfile.lock file
// see: https://guides.cocoapods.org/using/using-cocoapods.html#what-is-podfilelock
type PodfileLockParser struct{}

func NewPodfileLockParser() *PodfileLockParser {
	return &PodfileLockParser{}
}

func (p *PodfileLockParser) Matcher() collector.FileMatcher {
	return &collector.FileNameMatcher{Names: []string{"Podfile.lock"}}
}

type podfileLock struct {
	Pods         []interface{} `yaml:"PODS"`
	Dependencies []string      `yaml:"DEPENDENCIES"`
}

func (p *PodfileLockParser) Parse(path string) ([]model.Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := yaml.NewDecoder(file)

	lockfile := &podfileLock{}
	err = decoder.Decode(lockfile)
	if err != nil {
		return nil, err
	}

	depTree := collector.NewDependencyTree()

	depMap := make(map[string][]string)

	for i := 0; i < len(lockfile.Pods); i++ {
		name, version, deps := parsePackage(lockfile.Pods[i])
		if len(name) > 0 {
			pkg := newPackage(name, version, path)
			depTree.AddPackage(pkg)
			if len(deps) > 0 {
				depMap[pkg.PURL] = deps
			}
		}
	}
	for purl, deps := range depMap {
		pkg := depTree.GetPackage(purl)
		if pkg != nil {
			for _, dep := range deps {
				pkgs := depTree.GetPackagesByName(dep)
				if len(pkgs) > 0 {
					depTree.AddDependency(purl, pkgs[0].PURL)
				}
			}
		}
	}
	pkgs := depTree.ToList()
	return pkgs, nil
}

func parsePackage(podObj interface{}) (name, version string, deps []string) {
	nameAndVer := ""
	switch podItem := podObj.(type) {
	case string:
		nameAndVer = podItem
	case map[string]interface{}:
		for key, value := range podItem {
			nameAndVer = key
			if items, ok1 := value.([]interface{}); ok1 {
				for i := 0; i < len(items); i++ {
					if dep, ok2 := items[i].(string); ok2 {
						deps = append(deps, strings.SplitN(dep, " ", 2)[0])
					}
				}
			}
			break
		}
	}
	segs := strings.Split(nameAndVer, " ")
	if len(segs) >= 2 {
		name = strings.TrimSpace(segs[0])
		version = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(segs[1], "("), ")"))
		version = getVersion(version)
	} else {
		name = strings.TrimSpace(segs[0])
	}
	return
}
