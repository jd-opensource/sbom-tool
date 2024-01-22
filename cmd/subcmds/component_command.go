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

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/sbom"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var (
	// componentConfig is the config for component command
	componentConfig = &config.GenerateConfig{Parallelism: config.DefaultParallelism}
	// componentCmd represents the component command
	componentCmd = &cobra.Command{
		Use:   "component",
		Short: "generate component sbom document",
		Long:  "",
		Run:   runComponentCmd,
		Example: config.APPNAME +
			" component -m 4 -p /path/to/project -s /path/to/source -d /path/to/dist " +
			" -l java -o sbom.spdx.json -f spdx-json --ignore-dirs .git  " +
			" -n app -v 1.0 -u company -b https://example.com/sbom/xxx",
		PreRun: func(cmd *cobra.Command, args []string) {
			// set parallelism
			componentConfig.SourceConfig.Parallelism = componentConfig.Parallelism
			componentConfig.ArtifactConfig.Parallelism = componentConfig.Parallelism
			// init ignore dirs
			componentConfig.SourceConfig.InitIgnoreDirs()
		},
	}
)

var compExts = []string{".rpm", ".deb"}

// runComponentCmd is the entry of component command
func runComponentCmd(_ *cobra.Command, _ []string) {

	if !util.SliceAny(compExts, func(ext string) bool {
		return strings.HasSuffix(componentConfig.Path, ext)
	}) {
		log.Fatalf("only support for rpm,deb,jar file")
	}

	format := spec.GetFormat(componentConfig.Format)
	if format == nil {
		log.Warnf("supported formats: %s", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("format not supported! %s\n", componentConfig.Format)
	}
	if len(componentConfig.Path) == 0 {
		log.Fatalf("component path is blank")
	}
	componentConfig.DistPath = componentConfig.Path
	_, err := os.Stat(componentConfig.Path)
	if err != nil {
		log.Fatalf("component path is invalid")
	}
	log.Quietf("generating sbom(%s): %s", componentConfig.Format, componentConfig.Path)
	newSBOM, err := sbom.GenerateComponentSBOM(componentConfig)
	if err != nil {
		log.Fatalf("component sbom error: %s", err.Error())
	}
	// convert to target format from inner model
	format.Spec().FromModel(newSBOM)

	output := componentConfig.Output
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
	// add flags for component command
	componentCmd.PersistentFlags().IntVarP(&componentConfig.Parallelism, "parallelism", "m", config.DefaultParallelism,
		"number of parallelism")

	componentCmd.PersistentFlags().StringVarP(&componentConfig.SrcPath, "src", "s", "",
		"project source directory(use project root if empty)")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.Language, "language", "l", "*",
		"specify language(sample: java,cpp)")
	componentCmd.PersistentFlags().StringVar(&componentConfig.SourceConfig.IgnoreDirs, "ignore-src", "",
		"dirs to ignore for source, skip all dot dirs, split by comma. sample: node_modules,logs")

	componentCmd.PersistentFlags().StringVarP(&componentConfig.PackageName, "name", "n", "", "package name of artifact")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.PackageVersion, "version", "v", "",
		"package version of artifact")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.PackageSupplier, "supplier", "u", "",
		"package supplier of artifact")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.NamespaceURI, "namespace", "b", "",
		"document namespace base uri")

	componentCmd.PersistentFlags().BoolVarP(&componentConfig.ExtractFiles, "extract", "x", true, "extract files(only for a single zip,rpm,deb file)")

	componentCmd.PersistentFlags().StringVarP(&componentConfig.Path, "path", "p", ".", "project root path")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.Format, "format", "f", "spdx-json", "sbom document format")
	componentCmd.PersistentFlags().StringVarP(&componentConfig.Output, "output", "o", "", "output sbom file")

	_ = componentCmd.MarkPersistentFlagRequired("path")

}
