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
	"gitee.com/jd-opensource/sbom-tool/pkg/spec"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	// validateConfig is the config for validate command
	validateConfig = config.ValidateConfig{}
	// validateCmd represents the validate command
	validateCmd = &cobra.Command{
		Use:     "validate",
		Short:   "validate sbom document format",
		Long:    "",
		Run:     runValidateCmd,
		Example: config.APPNAME + " validate -i /path/to/sbom -f spdx-json -o result.json",
	}
)

type ValidateResult struct {
	Data     map[string]string `json:"data"`
	ErrorMsg string            `json:"errorMsg"`
}

// runValidateCmd is the entry of validate command
func runValidateCmd(_ *cobra.Command, _ []string) {
	if len(validateConfig.Format) == 0 {
		log.Fatalf("format is blank")
	}
	result := ValidateResult{}
	output := validateConfig.Output

	format := spec.GetFormat(validateConfig.Format)
	if format == nil {
		log.Infof("supported formats: %s", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("format not supported! %s\n", validateConfig.Format)
	}
	log.Quietf("loading file: %s", validateConfig.Input)
	file, err := os.Open(validateConfig.Input)
	if err != nil {
		log.Fatalf("open file error: %s\n", validateConfig.Input)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	err = format.Load(file)
	if err != nil {
		log.Fatalf("load file error: %s\n", validateConfig.Input)
	}
	err = format.Spec().Validate()
	if err != nil {
		result.ErrorMsg = err.Error()
		writeValidateResult(output, result)
		log.Fatalf("validate sbom document error: %s\n", err.Error())
	}
	log.Quietf("validated success")

	meta := format.Spec().Metadata()
	result.Data = meta
	writeValidateResult(output, result)
}

func writeValidateResult(output string, result ValidateResult) {
	if len(output) == 0 {
		if len(result.Data) > 0 {
			for k, v := range result.Data {
				fmt.Printf("\t%s\t: %s\n", k, v)
			}
		}
		if len(result.ErrorMsg) > 0 {
			log.Quietf("validate error: " + result.ErrorMsg)
		}
	} else {
		output, _ = filepath.Abs(output)
		log.Quietf("writing to file: %s", output)
		err := util.WriteToJSONFile(output, result)
		if err != nil {
			log.Fatalf("save file error: %s", output)
		}
		log.Quietf("finish")
	}
}

func init() {
	// add flags for validate command
	validateCmd.PersistentFlags().StringVarP(&validateConfig.Input, "input", "i", "", "input sbom document")
	validateCmd.PersistentFlags().StringVarP(&validateConfig.Format, "format", "f", "",
		"the sbom document format to validate")
	validateCmd.PersistentFlags().StringVarP(&validateConfig.Output, "output", "o", "", "output result to file")
	_ = validateCmd.MarkPersistentFlagRequired("input")
	_ = validateCmd.MarkPersistentFlagRequired("format")
}
