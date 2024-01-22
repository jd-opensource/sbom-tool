// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package log

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
)

var (
	logger *zap.Logger
	quiet  bool
)

func init() {
	InitLogger(config.NewLogConfig())
}

// InitLogger initializes the logger.
func InitLogger(cfg *config.LogConfig) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	// create directory if not exist
	dirPath := filepath.Dir(cfg.LogPath)
	_, e := os.Stat(dirPath)
	if e != nil {
		if os.IsNotExist(e) {
			_ = os.MkdirAll(dirPath, os.ModePerm)
		}
	}
	logFile, _ := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	writer := zapcore.AddSync(logFile)
	var core zapcore.Core

	logLevel, err := zapcore.ParseLevel(cfg.LogLevel)
	if err != nil {
		logLevel = zapcore.InfoLevel
	}
	quiet = cfg.Quiet
	if cfg.Quiet {
		core = zapcore.NewTee(
			zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), writer, logLevel),
		)
	} else {
		core = zapcore.NewTee(
			zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), writer, logLevel),
			zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), zapcore.AddSync(os.Stdout), logLevel),
		)
	}

	logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1), zap.AddStacktrace(zapcore.ErrorLevel))
}

func IsQuiet() bool {
	return quiet
}

// Infof logs a message at info level.
func Infof(tmpl string, args ...interface{}) {
	logger.Sugar().Infof(tmpl, args...)
}

// Quietf logs a message at info level. Will also output simple message to the console in quiet mode
func Quietf(tmpl string, args ...interface{}) {
	logger.Sugar().Infof(tmpl, args...)
	if quiet {
		fmt.Printf(tmpl, args...)
	}
}

// Debugf logs a message at debug level.
func Debugf(tmpl string, args ...interface{}) {
	logger.Sugar().Debugf(tmpl, args...)
}

// Warnf logs a message at warn level.
func Warnf(tmpl string, args ...interface{}) {
	logger.Sugar().Warnf(tmpl, args...)
}

// Errorf logs a message at error level.
func Errorf(tmpl string, args ...interface{}) {
	if quiet {
		fmt.Printf(tmpl, args...)
	}
	logger.Sugar().Errorf(tmpl, args...)
}

// Panicf logs a message at panic level. And then panics.
func Panicf(tmpl string, args ...interface{}) {
	if quiet {
		fmt.Printf(tmpl, args...)
	}
	logger.Sugar().Panicf(tmpl, args...)
}

// Fatalf logs a message at fatal level. The os.Exit(1) is called at the end.
// Due to os. Exit() being called, the defer function will not be called.
func Fatalf(tmpl string, args ...interface{}) {
	if quiet {
		fmt.Printf(tmpl, args...)
	}
	logger.Sugar().Fatalf(tmpl, args...)
}
