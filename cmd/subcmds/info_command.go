// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package subcmds

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/fingerprint"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

const InfoLinePrefix = "- "

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:     "info",
	Short:   "get tool introduction information",
	Long:    "",
	Run:     runInfoCmd,
	Example: config.APPNAME + " info",
}

// runInfoCmd Get tool introduction information
func runInfoCmd(_ *cobra.Command, _ []string) {
	fmt.Println(config.AppNameVersion())
	fmt.Println(config.APPDESC)
	fmt.Println()

	// Supported code fingerprint programming language
	fmt.Println("Supported code fingerprint programming language:")
	fingerprintLanguages := make([]string, 0)
	for _, processor := range fingerprint.AllPreProcessors() {
		fingerprintLanguages = append(fingerprintLanguages, processor.Name())
	}
	sortAndOutput(fingerprintLanguages)
	fmt.Println()
	fmt.Println("Supported package collectors:")
	collectorInfos := make([]string, 0)
	for _, c := range pckg.AllCollectors() {
		parsers := c.GetParsers()
		parserDescs := util.SliceMap(parsers, func(p collector.FileParser) string {
			return p.Matcher().Description()
		})
		info := fmt.Sprintf("%s\n\t%s", c.GetName(), strings.Join(parserDescs, "\n\t"))
		collectorInfos = append(collectorInfos, info)
	}
	sortAndOutput(collectorInfos)
	fmt.Println()
	// Supported SBOM document formats
	fmt.Println("Supported SBOM document formats:")
	formatNames := spec.AllFormatNames()
	sortAndOutput(formatNames)
}

func sortAndOutput(items []string) {
	sort.Slice(items, func(i, j int) bool {
		return items[i][0] < items[j][0]
	})
	for _, v := range items {
		fmt.Println(InfoLinePrefix + v)
	}
}

func init() {
}
