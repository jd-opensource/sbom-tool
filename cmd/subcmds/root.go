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

	"github.com/spf13/cobra"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	logConfig = &config.LogConfig{}
	rootCmd   = &cobra.Command{
		Use:           config.APPNAME,
		Short:         config.APPNAME + " - " + config.APPDESC,
		Long:          "",
		Version:       config.VERSION,
		SilenceErrors: false,
		SilenceUsage:  false,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			log.InitLogger(logConfig)
		},
	}
)

func init() {
	logPath := config.DefaultLogPath()
	// add flags for rootCmd
	rootCmd.PersistentFlags().StringVar(&logConfig.LogPath, "log-path", logPath, "log output path")
	rootCmd.PersistentFlags().StringVar(&logConfig.LogLevel, "log-level", "info", "log level")
	rootCmd.PersistentFlags().BoolVarP(&logConfig.Quiet, "quiet", "q", false, "no console output")

	// add sub commands
	rootCmd.AddCommand(sourceCmd)
	rootCmd.AddCommand(packageCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(artifactCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(componentCmd)
	rootCmd.AddCommand(assemblyCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(modifyCmd)
	rootCmd.AddCommand(infoCmd)
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return fmt.Errorf("execute commmad error: %w", err)
	}
	return nil
}
