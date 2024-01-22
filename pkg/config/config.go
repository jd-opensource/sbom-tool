// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/util/pattern_set"
)

// APPNAME is the name of the application
const APPNAME = "sbom-tool"

const APPDESC = "CLI tool for generating SBOM"

// VERSION is the version of the application
var VERSION = "(dev)"

// LogConfig is the configuration for logging
type LogConfig struct {
	LogPath  string
	LogLevel string
	Quiet    bool
}

// SourceConfig is the configuration for source subcommand
type SourceConfig struct {
	Path          string
	Parallelism   int
	SrcPath       string
	Output        string
	Mode          string
	Language      string
	IgnoreDirs    string
	ignoreDirsSet *pattern_set.PatternSet
}

// PackageConfig is the configuration for package subcommand
type PackageConfig struct {
	Parallelism   int
	Collectors    string
	Path          string
	Output        string
	IgnoreDirs    string
	ignoreDirsSet *pattern_set.PatternSet
}

// ArtifactConfig is the configuration for artifact subcommand
type ArtifactConfig struct {
	Parallelism     int
	PackageName     string
	PackageVersion  string
	PackageSupplier string
	DistPath        string
	Output          string
	ExtractFiles    bool
	IgnoreDirs      string
	ignoreDirsSet   *pattern_set.PatternSet
}

// AssemblyConfig is the configuration for assembly subcommand
type AssemblyConfig struct {
	Path         string
	Format       string
	Output       string
	NamespaceURI string
}

// GenerateConfig is the configuration for generate subcommand
type GenerateConfig struct {
	SourceConfig
	PackageConfig
	ArtifactConfig
	AssemblyConfig
	NamespaceURI string
	IgnoreSrc    string
	IgnoreDist   string
	IgnorePkg    string
	SkipPhases   string
	Path         string
	Parallelism  int
	Output       string
}

// ConvertConfig is the configuration for convert subcommand
type ConvertConfig struct {
	Input    string
	Original string
	Format   string
	Output   string
}

// ValidateConfig is the configuration for validate subcommand
type ValidateConfig struct {
	Input  string
	Format string
	Output string
}

// ModifyConfig is the configuration for modify subcommand
type ModifyConfig struct {
	Input  string
	Format string
	Output string
	Update map[string]*[]string
}

// DefaultParallelism is the default value of parallelism
const DefaultParallelism = 8

// NewLogConfig returns a new LogConfig
func NewLogConfig() *LogConfig {
	logPath := DefaultLogPath()

	logDir := path.Dir(logPath)
	_, err := os.Stat(logDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(logDir, os.ModePerm)
		if err != nil {
			fmt.Println("log path invalid")
		}
	}
	return &LogConfig{
		LogPath:  logPath,
		LogLevel: "info",
		Quiet:    true,
	}
}

func initIgnoreDirs(rootPath string, ignoreDirs string) *pattern_set.PatternSet {
	ignoreDirsSet := pattern_set.NewPrefixPatternMatchSet()
	dirs := strings.Split(ignoreDirs, ",")

	// force ignore all dot dirs
	dirs = append(dirs, ".")

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if filepath.IsAbs(dir) {
			if strings.HasPrefix(dir, rootPath) {
				ignoreDirsSet.Add(dir)
			}
		} else {
			ignoreDirsSet.Add(fmt.Sprintf("%s%c%s", rootPath, os.PathSeparator, dir))
		}
	}
	return ignoreDirsSet
}

// InitIgnoreDirs initializes the ignoreDirsSet
func (cfg *SourceConfig) InitIgnoreDirs() {
	cfg.SrcPath = resolveScanRoot(cfg.SrcPath)
	cfg.ignoreDirsSet = initIgnoreDirs(cfg.SrcPath, cfg.IgnoreDirs)
}

// IgnoreDirsSet returns the ignoreDirsSet
func (cfg *SourceConfig) IgnoreDirsSet() *pattern_set.PatternSet {
	return cfg.ignoreDirsSet
}

// InitIgnoreDirs initializes the ignoreDirsSet
func (cfg *ArtifactConfig) InitIgnoreDirs() {
	cfg.DistPath = resolveScanRoot(cfg.DistPath)
	cfg.ignoreDirsSet = initIgnoreDirs(cfg.DistPath, cfg.IgnoreDirs)
}

// IgnoreDirsSet returns the ignoreDirsSet
func (cfg *ArtifactConfig) IgnoreDirsSet() *pattern_set.PatternSet {
	return cfg.ignoreDirsSet
}

// InitIgnoreDirs initializes the ignoreDirsSet
func (cfg *PackageConfig) InitIgnoreDirs() {
	cfg.Path = resolveScanRoot(cfg.Path)
	cfg.ignoreDirsSet = initIgnoreDirs(cfg.Path, cfg.IgnoreDirs)
}

// IgnoreDirsSet returns the ignoreDirsSet
func (cfg *PackageConfig) IgnoreDirsSet() *pattern_set.PatternSet {
	return cfg.ignoreDirsSet
}

func resolveScanRoot(root string) string {
	if root == "" {
		return ""
	}
	scanRoot := strings.TrimSuffix(root, string(os.PathSeparator))
	if scanRoot == "." {
		pwd, _ := os.Getwd()
		scanRoot = pwd
	}
	scanRoot, _ = filepath.Abs(scanRoot)
	return scanRoot
}

// UserAppHome returns the home directory of the application
func UserAppHome() string {
	home, _ := os.UserHomeDir()
	return path.Join(home, APPNAME)
}

// DefaultLogPath returns the default log path
func DefaultLogPath() string {
	return path.Join(UserAppHome(), APPNAME+".log")
}

func AppNameVersion() string {
	return APPNAME + " " + VERSION
}
