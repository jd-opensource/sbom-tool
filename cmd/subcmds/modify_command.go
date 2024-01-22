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
	// modifyConfig is the config for modify command
	modifyConfig = &config.ModifyConfig{}
	// modifyCmd represents the modify command
	modifyCmd = &cobra.Command{
		Use:     "modify",
		Short:   "modify sbom document properties",
		Long:    "",
		Run:     runModifyCmd,
		Example: config.APPNAME + " modify -i /path/to/sbom -f spdx-json -o sbom.spdx.json",
	}
)

// runModifyCmd is the entry of modify command
func runModifyCmd(_ *cobra.Command, _ []string) {
	if len(modifyConfig.Input) == 0 {
		log.Fatalf("input sbom doc path is blank")
	}
	stat, err := os.Stat(modifyConfig.Input)
	if err != nil {
		log.Fatalf("input sbom doc path is invalid")
	}
	if stat.IsDir() {
		log.Fatalf("input sbom doc path is not a file")
	}

	format := spec.GetFormat(modifyConfig.Format)
	if format == nil {
		log.Infof("supported formats: %s", strings.Join(spec.AllFormatNames(), ","))
		log.Fatalf("modify format not supported! %s", modifyConfig.Format)
	}
	log.Quietf("modifying to %s: %s", modifyConfig.Format, modifyConfig.Input)
	format, err = sbom.ModifySBOM(modifyConfig)
	if err != nil {
		log.Fatalf("modify sbom error: %s", err.Error())
	}
	output := modifyConfig.Output
	if len(output) == 0 {
		input := modifyConfig.Input
		ext := filepath.Ext(input)
		output = fmt.Sprintf("%s-new.%s", input[:len(input)-len(ext)], ext)
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
	modifyCmd.PersistentFlags().StringVarP(&modifyConfig.Input, "input", "i", "", "input sbom document")
	modifyCmd.PersistentFlags().StringVarP(&modifyConfig.Format, "format", "f", "", "the sbom document format modify to")
	modifyCmd.PersistentFlags().StringVarP(&modifyConfig.Output, "output", "o", "", "output sbom document")

	updaters := spec.AllUpdaterDesc()
	if len(updaters) > 0 {
		modifyConfig.Update = make(map[string]*[]string)
		for name, desc := range updaters {
			v := make([]string, 0)
			modifyConfig.Update[name] = &v
			modifyCmd.PersistentFlags().StringArrayVar(&v, name, nil, desc)
		}
	}

	_ = modifyCmd.MarkPersistentFlagRequired("input")
	_ = modifyCmd.MarkPersistentFlagRequired("format")
}
