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
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var (
	// assemblyConfig is the config for assembly command
	assemblyConfig = &config.AssemblyConfig{}
	// assemblyCmd represents the assembly command
	assemblyCmd = &cobra.Command{
		Use:     "assembly",
		Short:   "assembly sbom document from document segments",
		Long:    "",
		Run:     runAssemblyCmd,
		Example: config.APPNAME + " assembly -p /path/to/segments -o sbom.spdx.json -f spdx-json",
	}
)

// runAssemblyCmd is the main function for assembly command
func runAssemblyCmd(_ *cobra.Command, _ []string) {
	if len(assemblyConfig.Path) == 0 {
		log.Fatalf("sbom segments dir path is blank")
	}
	stat, err := os.Stat(assemblyConfig.Path)
	if err != nil {
		log.Fatalf("sbom segments dir path is invalid: %s", assemblyConfig.Format)
	}
	if !stat.IsDir() {
		log.Fatalf("sbom segments dir path is not a dir: %s", assemblyConfig.Format)
	}
	format := spec.GetFormat(assemblyConfig.Format)
	if format == nil {
		log.Infof("supported formats:", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("format not supported! %s\n", assemblyConfig.Format)
	}
	log.Quietf("assembling sbom (%s): %s", assemblyConfig.Format, assemblyConfig.Path)
	newSBOM, err := sbom.AssemblySBOM(assemblyConfig)
	if err != nil {
		log.Fatalf("assembly sbom error: %s", err.Error())
	}
	// convert to target format from inner model
	format.Spec().FromModel(newSBOM)

	output := assemblyConfig.Output
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
	log.Infof("writing to file: %s", output)
	err = format.Dump(file)
	if err != nil {
		log.Fatalf("save file error: %s\n", output)
	}
	log.Infof("finish")
}

func init() {
	// add flags for assembly command
	assemblyCmd.PersistentFlags().StringVarP(&assemblyConfig.Path, "path", "p", ".", "sbom segments dir")
	assemblyCmd.PersistentFlags().StringVarP(&assemblyConfig.Format, "format", "f", "spdx-json", "sbom document format")
	assemblyCmd.PersistentFlags().StringVarP(&assemblyConfig.Output, "output", "o", "", "distribution directory")
	assemblyCmd.PersistentFlags().StringVarP(&assemblyConfig.NamespaceURI, "namespace", "b", "",
		"document namespace base uri")
	_ = assemblyCmd.MarkPersistentFlagRequired("path")
}
