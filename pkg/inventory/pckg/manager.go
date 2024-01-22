// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pckg

import (
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

// CollectorManager manages all Parsers
type CollectorManager struct {
	cfg *config.PackageConfig
}

// NewCollectorManager creates a new CollectorManager
func NewCollectorManager(cfg *config.PackageConfig) *CollectorManager {
	manager := &CollectorManager{
		cfg: cfg,
	}
	return manager
}

// Collect packages using given collectors
func (cm *CollectorManager) Collect(dirPath string) ([]model.Package, error) {
	enabledCollectors := GetCollectors(cm.cfg.Collectors)
	collectorNames := util.SliceMap(enabledCollectors, func(c collector.Collector) string {
		return c.GetName()
	})
	log.Infof("enabled package collectors: %s", strings.Join(collectorNames, ","))
	ignoreMatcher := cm.cfg.IgnoreDirsSet()
	err := filepath.WalkDir(dirPath, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ignoreMatcher != nil && ignoreMatcher.Match(file) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		richFile := collector.NewFileMeta(file)
		for _, collector := range enabledCollectors {
			collector.TryToAccept(richFile)
		}
		return nil
	})
	if err != nil {
		log.Errorf("walk dirPath error: %s\n", err.Error())
		return nil, err
	}

	resultChan := make(chan []model.Package)

	matchedCollectors := util.SliceFilter(enabledCollectors, func(collector collector.Collector) bool {
		return len(collector.GetRequests()) > 0
	})
	var wg sync.WaitGroup
	wg.Add(len(matchedCollectors))

	for idx := range matchedCollectors {
		go func(index int) {
			result, err := matchedCollectors[index].Collect()
			if err != nil {
				log.Errorf("collect package error: %s\n", err.Error())
			}
			resultChan <- result
			wg.Done()
		}(idx)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var pkgs []model.Package
	for r := range resultChan {
		logPkgs(r)
		pkgs = append(pkgs, r...)
	}
	pkgs = collector.OrganizePackage(pkgs)

	//pkg中去掉路径前缀
	for i := 0; i < len(pkgs); i++ {
		if pkgs[i].SourceLocation != "" {
			pkgs[i].SourceLocation = strings.TrimPrefix(pkgs[i].SourceLocation, dirPath)
			pkgs[i].SourceLocation = strings.TrimPrefix(pkgs[i].SourceLocation, "/")
		}
	}
	return pkgs, nil
}

func logPkgs(pkgs []model.Package) {
	for i := 0; i < len(pkgs); i++ {
		log.Debugf("package info { name: %s, version: %s, type: %s, dependencies: %d}",
			pkgs[i].Name, pkgs[i].Version, pkgs[i].Type, len(pkgs[i].Dependencies))
	}
}
