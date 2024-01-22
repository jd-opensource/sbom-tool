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
	// convertConfig is the config for convert command
	convertConfig = &config.ConvertConfig{}
	// convertCmd represents the convert command
	convertCmd = &cobra.Command{
		Use:     "convert",
		Short:   "convert sbom document format",
		Long:    "",
		Run:     runConvertCmd,
		Example: config.APPNAME + " convert -i /path/to/sbom -g xspdx-json -f spdx-json -o sbom.spdx.json",
	}
)

// runConvertCmd is the entry of convert command
func runConvertCmd(_ *cobra.Command, _ []string) {
	if len(convertConfig.Input) == 0 {
		log.Fatalf("input sbom doc path is blank")
	}
	stat, err := os.Stat(convertConfig.Input)
	if err != nil {
		log.Fatalf("input sbom doc path is invalid")
	}
	if stat.IsDir() {
		log.Fatalf("input sbom doc path is not a file")
	}

	if len(convertConfig.Original) > 0 {
		original := spec.GetFormat(convertConfig.Original)
		if original == nil {
			log.Infof("supported formats: %s", strings.Join(spec.AllFormatNames(), ","))
			log.Fatalf("original format not supported! %s", convertConfig.Original)
		}
	}

	format := spec.GetFormat(convertConfig.Format)
	if format == nil {
		log.Infof("supported formats: %s", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("convert format not supported! %s", convertConfig.Format)
	}
	log.Quietf("converting to %s: %s", convertConfig.Format, convertConfig.Input)
	newSBOM, err := sbom.ConvertSBOM(convertConfig)
	if err != nil {
		log.Fatalf("convert sbom doc error: %s", err.Error())
	}
	// convert to target format from inner model
	format.Spec().FromModel(newSBOM)

	output := convertConfig.Output
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
		log.Fatalf("save file error: %s\n", output)
	}
	log.Quietf("finish")
}

func init() {
	// add flags
	convertCmd.PersistentFlags().StringVarP(&convertConfig.Input, "input", "i", "", "input sbom document")
	convertCmd.PersistentFlags().StringVarP(&convertConfig.Original, "original", "g", "",
		"the sbom document format convert from")
	convertCmd.PersistentFlags().StringVarP(&convertConfig.Format, "format", "f", "",
		"the sbom document format convert to")
	convertCmd.PersistentFlags().StringVarP(&convertConfig.Output, "output", "o", "", "output sbom document")

	_ = convertCmd.MarkPersistentFlagRequired("input")
	_ = convertCmd.MarkPersistentFlagRequired("format")
}
