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

	"github.com/spf13/cobra"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/sbom"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	// generateConfig is the config for generate command
	generateConfig = &config.GenerateConfig{Parallelism: config.DefaultParallelism}
	// generateCmd represents the generate command
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate sbom document",
		Long:  "",
		Run:   runGenerateCmd,
		Example: config.APPNAME +
			" generate -m 4 -p /path/to/project -s /path/to/source -d /path/to/dist " +
			" -l java -o sbom.spdx.json -f spdx-json --ignore-dirs .git  " +
			" -n app -v 1.0 -u company -b https://example.com/sbom/xxx",
		PreRun: func(cmd *cobra.Command, args []string) {
			// set parallelism
			generateConfig.SourceConfig.Parallelism = generateConfig.Parallelism
			generateConfig.PackageConfig.Parallelism = generateConfig.Parallelism
			generateConfig.ArtifactConfig.Parallelism = generateConfig.Parallelism
			generateConfig.SourceConfig.Path = generateConfig.Path
			generateConfig.PackageConfig.Path = generateConfig.Path
			// init ignore dirs
			generateConfig.SourceConfig.InitIgnoreDirs()
			generateConfig.PackageConfig.InitIgnoreDirs()
			generateConfig.ArtifactConfig.InitIgnoreDirs()
		},
	}
)

// runGenerateCmd is the entry of generate command
func runGenerateCmd(_ *cobra.Command, _ []string) {
	format := spec.GetFormat(generateConfig.Format)
	if format == nil {
		log.Warnf("supported formats:", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("format not supported! %s\n", generateConfig.Format)
	}
	if len(generateConfig.Path) == 0 && len(generateConfig.SrcPath) == 0 {
		log.Fatalf("project root and source path is blank")
	}
	if len(generateConfig.Path) == 0 {
		log.Warnf("project root is blank, use source path: %s", sourceConfig.SrcPath)
		sourceConfig.Path = sourceConfig.SrcPath
	}
	if len(generateConfig.SrcPath) == 0 {
		log.Warnf("source path is blank, use project root: %s", sourceConfig.Path)
		sourceConfig.SrcPath = sourceConfig.Path
	}
	if len(generateConfig.DistPath) == 0 {
		log.Fatalf("distribution path is blank")
	}
	_, err := os.Stat(generateConfig.DistPath)
	if err != nil {
		log.Fatalf("distribution path is invalid")
	}
	log.Quietf("generating sbom(%s): %s", generateConfig.Format, generateConfig.Path)
	newSBOM, err := sbom.GenerateSBOM(generateConfig)
	if err != nil {
		log.Fatalf("generate sbom error: %s", err.Error())
	}
	// convert to target format from inner model
	format.Spec().FromModel(newSBOM)

	output := generateConfig.Output
	if len(output) == 0 {
		output = fmt.Sprintf("sbom-%s.%s", format.Spec().Name(), format.Type())
	}
	output, _ = filepath.Abs(output)
	file, err := os.Create(output)
	if err != nil {
		log.Fatalf("create file error: %s\n", output)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	log.Quietf("writing to file: %s", output)
	err = format.Dump(file)
	if err != nil {
		log.Fatalf("save file error: %s\n", err.Error())
	}
	log.Quietf("finish")
}

func init() {
	// add flags for generate command
	generateCmd.PersistentFlags().IntVarP(&generateConfig.Parallelism, "parallelism", "m", config.DefaultParallelism,
		"number of parallelism")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.SrcPath, "src", "s", ".",
		"project source directory(use project root if empty)")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.Language, "language", "l", "*",
		"specify language(sample: java,cpp)")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.Collectors, "collectors", "c", "*", "enable package collectors")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.SkipPhases, "skip", "", "", "skip some phases.(one of source|package|artifact)")
	generateCmd.PersistentFlags().StringVar(&generateConfig.SourceConfig.IgnoreDirs, "ignore-src", "",
		"dirs to ignore for source, skip all dot dirs, split by comma. sample: node_modules,logs")
	generateCmd.PersistentFlags().StringVar(&generateConfig.PackageConfig.IgnoreDirs, "ignore-pkg", "",
		"dirs to ignore for package, skip all dot dirs, split by comma. sample: node_modules,logs")
	generateCmd.PersistentFlags().StringVar(&generateConfig.ArtifactConfig.IgnoreDirs, "ignore-dist", "",
		"dirs to ignore for dist, skip all dot dirs, split by comma. sample: node_modules,logs")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.DistPath, "dist", "d", "./dist", "distribution directory")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.PackageName, "name", "n", "", "package name of artifact")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.PackageVersion, "version", "v", "",
		"package version of artifact")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.PackageSupplier, "supplier", "u", "",
		"package supplier of artifact")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.NamespaceURI, "namespace", "b", "",
		"document namespace base uri")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.Path, "path", "p", ".", "project root path")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.Format, "format", "f", "spdx-json", "sbom document format")
	generateCmd.PersistentFlags().StringVarP(&generateConfig.Output, "output", "o", "", "output sbom file")

	generateCmd.PersistentFlags().BoolVarP(&generateConfig.ExtractFiles, "extract", "x", false, "extract files(only for a single zip,rpm,deb file)")

	_ = generateCmd.MarkPersistentFlagRequired("path")
	_ = generateCmd.MarkPersistentFlagRequired("dist")
	_ = generateCmd.MarkPersistentFlagRequired("name")
	_ = generateCmd.MarkPersistentFlagRequired("version")
	_ = generateCmd.MarkPersistentFlagRequired("supplier")
	_ = generateCmd.MarkPersistentFlagRequired("namespace")
}
