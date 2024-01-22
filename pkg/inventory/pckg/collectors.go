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
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/bower"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/cargo"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/carthage"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/cocoapods"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/composer"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/conan"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/conda"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/deb"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/dylib"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/gem"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/golang"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/lua"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/maven"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/npm"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/nuget"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/pub"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/pypi"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/rpm"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/swift"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

func AllCollectors() []collector.Collector {
	var allCollectors []collector.Collector
	allCollectors = append(allCollectors, bower.NewCollector())
	allCollectors = append(allCollectors, cargo.NewCollector())
	allCollectors = append(allCollectors, carthage.NewCollector())
	allCollectors = append(allCollectors, cocoapods.NewCollector())
	allCollectors = append(allCollectors, composer.NewCollector())
	allCollectors = append(allCollectors, conan.NewCollector())
	allCollectors = append(allCollectors, conda.NewCollector())
	allCollectors = append(allCollectors, gem.NewCollector())
	allCollectors = append(allCollectors, golang.NewCollector())
	allCollectors = append(allCollectors, lua.NewCollector())
	allCollectors = append(allCollectors, maven.NewCollector())
	allCollectors = append(allCollectors, npm.NewCollector())
	allCollectors = append(allCollectors, nuget.NewCollector())
	allCollectors = append(allCollectors, pub.NewCollector())
	allCollectors = append(allCollectors, pypi.NewCollector())
	allCollectors = append(allCollectors, rpm.NewCollector())
	allCollectors = append(allCollectors, swift.NewCollector())
	allCollectors = append(allCollectors, dylib.NewCollector())
	allCollectors = append(allCollectors, deb.NewCollector())
	return allCollectors
}

// GetCollectors groups for directory
func GetCollectors(names string) []collector.Collector {
	allCollectors := AllCollectors()
	names = strings.TrimSpace(names)
	if names == "" || names == "*" {
		return allCollectors
	}
	namesArr := strings.Split(names, ",")
	namesArr = util.SliceMap(namesArr, func(name string) string {
		return strings.TrimSpace(name)
	})
	namesArr = util.SliceFilter(namesArr, func(name string) bool {
		return name != ""
	})
	return util.SliceFilter(allCollectors, func(collector collector.Collector) bool {
		return slices.Contains(namesArr, collector.GetName())
	})
}
