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
	"github.com/spf13/cobra"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/env"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:     "env",
	Short:   "build environment info",
	Long:    "",
	Run:     runEnvCmd,
	Example: config.APPNAME + " env",
}

// runEnvCmd is the entry of env command
func runEnvCmd(_ *cobra.Command, _ []string) {
	envInfo := env.GetEnvInfo()
	log.Quietf("%s", envInfo.String())
}

func init() {
	// add flags
}
