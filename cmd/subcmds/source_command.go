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
	"path/filepath"

	"github.com/spf13/cobra"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/source"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var (
	// sourceConfig is the config for source command
	sourceConfig = &config.SourceConfig{}
	// sourceCmd represents the source command
	sourceCmd = &cobra.Command{
		Use:   "source",
		Short: "collect source code information",
		Long:  "",
		Example: config.APPNAME +
			" source -m 4 -s /path/to/source -l java -o source.json --output-mode singlefile --ignore-dirs .git",
		Run: runSourceCmd,
		PreRun: func(cmd *cobra.Command, args []string) {
			sourceConfig.InitIgnoreDirs()
		},
	}
)

func runSourceCmd(_ *cobra.Command, _ []string) {
	if len(sourceConfig.Path) == 0 && len(sourceConfig.SrcPath) == 0 {
		log.Fatalf("project root and source path is blank")
	}
	if len(sourceConfig.Path) == 0 {
		log.Warnf("project root is blank, use source path: %s", sourceConfig.SrcPath)
		sourceConfig.Path = sourceConfig.SrcPath
	}
	if len(sourceConfig.SrcPath) == 0 {
		log.Warnf("source path is blank, use project root: %s", sourceConfig.Path)
		sourceConfig.SrcPath = sourceConfig.Path
	}
	// get source info
	log.Quietf("collecting source info: %s", sourceConfig.Path)
	sourceInfo, err := source.GetSourceInfo(sourceConfig)
	if err != nil {
		log.Fatalf("get source info error: %s\n", err.Error())
	}
	output := sourceConfig.Output
	if len(output) == 0 {
		output = "source.json"
	}
	output, _ = filepath.Abs(output)
	log.Quietf("writing to file: %s", output)
	err = util.WriteToJSONFile(output, sourceInfo)
	if err != nil {
		log.Fatalf("save file error: %s\n", output)
	}
	log.Quietf("finish")
}

func init() {
	// add flags for source command
	sourceCmd.PersistentFlags().IntVarP(&sourceConfig.Parallelism, "parallelism", "m", config.DefaultParallelism,
		"number of parallelism")
	sourceCmd.PersistentFlags().StringVarP(&sourceConfig.Path, "path", "p", "",
		"project root path(use source path if empty)")
	sourceCmd.PersistentFlags().StringVarP(&sourceConfig.SrcPath, "src", "s", ".",
		"project source directory(use project root if empty)")
	sourceCmd.PersistentFlags().StringVar(&sourceConfig.IgnoreDirs, "ignore-dirs", "",
		"dirs to ignore, skip all dot dirs, split by comma. sample: node_modules,logs")
	sourceCmd.PersistentFlags().StringVarP(&sourceConfig.Output, "output", "o", "source.json", "output file")
	sourceCmd.PersistentFlags().StringVarP(&sourceConfig.Mode, "output-mode", "", "singlefile",
		"output mode, singlefile or multiplefile")
	sourceCmd.PersistentFlags().StringVarP(&sourceConfig.Language, "language", "l", "*",
		"specify language(sample: java,cpp)")

	_ = sourceCmd.MarkPersistentFlagRequired("src")
}
