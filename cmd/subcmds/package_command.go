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
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/pckg"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	noRecommendedLicenseCount int = 0
	// packageConfig is the config for package command
	packageConfig = &config.PackageConfig{Parallelism: config.DefaultParallelism}
	// packageCmd represents the package command
	packageCmd = &cobra.Command{
		Use:     "package",
		Short:   "collect package dependencies",
		Long:    "",
		Run:     runPackageCmd,
		Example: config.APPNAME + " package -m 4 -p /path/to/project -c maven,npm -o package.json",
		PreRun: func(cmd *cobra.Command, args []string) {
			packageConfig.InitIgnoreDirs()
		},
	}
)

// runPackageCmd is the entry of package command
func runPackageCmd(_ *cobra.Command, _ []string) {
	if len(packageConfig.Path) == 0 {
		log.Fatalf("project root path is blank")
	}
	stat, err := os.Stat(packageConfig.Path)
	if err != nil {
		log.Fatalf("project root path is invalid")
	}
	if !stat.IsDir() {
		log.Fatalf("project root path is not a dir")
	}
	log.Quietf("collecting package info: %s", packageConfig.Path)
	cm := pckg.NewCollectorManager(packageConfig)
	packages, err := cm.Collect(packageConfig.Path)

	if err != nil {
		log.Fatalf("collect package error: %s", err.Error())
	}

	output := packageConfig.Output

	printPackages(packages)
	if len(output) == 0 {
		return
	}

	output, _ = filepath.Abs(output)
	log.Quietf("writing to file: %s\n", output)
	err = util.WriteToJSONFile(output, packages)
	if err != nil {
		log.Fatalf("save file error: %s", output)
	}
	log.Quietf("finish")
}

func init() {
	// add flags for package command
	packageCmd.PersistentFlags().IntVarP(&packageConfig.Parallelism, "parallelism", "m", config.DefaultParallelism,
		"number of parallelism")
	packageCmd.PersistentFlags().StringVarP(&packageConfig.Path, "path", "p", ".", "project root path")
	packageCmd.PersistentFlags().StringVarP(&packageConfig.Collectors, "collectors", "c", "*", "enable package collectors")
	packageCmd.PersistentFlags().StringVarP(&packageConfig.Output, "output", "o", "", "output file(empty for only output to console)")

	_ = packageCmd.MarkPersistentFlagRequired("path")
}

func printPackages(pkgs []model.Package) {
	fmt.Println()
	writer := table.NewWriter()
	writer.SetColumnConfigs([]table.ColumnConfig{
		{Name: "#", WidthMax: 20},
		{Name: "Type", WidthMax: 20},
		{Name: "Name", WidthMax: 40},
		{Name: "Version", WidthMax: 35},
		{Name: "License", WidthMax: 30},
		{Name: "Source Location", WidthMax: 80},
	})

	writer.AppendHeader(table.Row{"#", "Type", "Name", "Version", "License", "Source Location"})
	for i, pkg := range pkgs {
		writer.AppendRow(table.Row{i + 1, pkg.Type, pkg.Name, pkg.Version, strings.Join(pkg.LicenseDeclared, " "), pkg.SourceLocation})
	}
	writer.SetCaption("Found %d packages.\n", len(pkgs))
	fmt.Println(writer.Render())
}
