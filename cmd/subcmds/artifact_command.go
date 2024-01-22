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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/artifact"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

var (
	// artifactConfig is the config for artifact command
	artifactConfig = &config.ArtifactConfig{}
	// artifactCmd represents the artifact command
	artifactCmd = &cobra.Command{
		Use:     "artifact",
		Short:   "collect artifact information",
		Long:    "",
		Run:     runArtifactCmd,
		Example: config.APPNAME + " artifact -m 4 -d /path/to/dist -o artifact.json -n app -v 1.0 -u company ",
		PreRun: func(cmd *cobra.Command, args []string) {
			artifactConfig.InitIgnoreDirs()
		},
	}
)

// runArtifactCmd is the main function for artifact command
func runArtifactCmd(_ *cobra.Command, _ []string) {
	if len(artifactConfig.DistPath) == 0 {
		log.Fatalf("distribution path is blank")
	}
	_, err := os.Stat(artifactConfig.DistPath)
	if err != nil {
		log.Fatalf("distribution path is invalid")
	}
	log.Quietf("collecting artifact info: %s", artifactConfig.DistPath)

	artifactInfo, err := artifact.Collect(artifactConfig, "")
	if err != nil {
		log.Fatalf("collect artifact info error: %s", err.Error())
	}
	output := artifactConfig.Output
	if len(output) == 0 {
		output = "artifact.json"
	}
	output, _ = filepath.Abs(output)
	log.Quietf("writing to file: %s", output)

	err = util.WriteToJSONFile(output, artifactInfo)
	if err != nil {
		log.Fatalf("save file error: %s", output)
	}
	log.Quietf("finish")
}

func init() {
	// add flags for artifact command
	artifactCmd.PersistentFlags().IntVarP(&artifactConfig.Parallelism, "parallelism", "m", config.DefaultParallelism,
		"number of parallelism")
	artifactCmd.PersistentFlags().StringVarP(&artifactConfig.DistPath, "dist", "d", ".",
		"distribution dir or artifact file")
	artifactCmd.PersistentFlags().StringVarP(&artifactConfig.PackageName, "name", "n", "",
		"package name of artifact")
	artifactCmd.PersistentFlags().StringVarP(&artifactConfig.PackageVersion, "version", "v", "",
		"package version of artifact")
	artifactCmd.PersistentFlags().StringVarP(&artifactConfig.PackageSupplier, "supplier", "u", "",
		"package supplier of artifact")
	artifactCmd.PersistentFlags().StringVarP(&artifactConfig.Output, "output", "o", "artifact.json", "output file")
	artifactCmd.PersistentFlags().BoolVarP(&artifactConfig.ExtractFiles, "extract", "x", false, "extract files(only for a single zip,rpm,deb file)")

	_ = artifactCmd.MarkPersistentFlagRequired("dist")
	_ = artifactCmd.MarkPersistentFlagRequired("name")
	_ = artifactCmd.MarkPersistentFlagRequired("version")
	_ = artifactCmd.MarkPersistentFlagRequired("supplier")
}
