// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package fingerprint

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/digester"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	preprocessorMap = make(map[string]preprocessor.PreProcessor)
)

const (
	LineSep          = "\n"
	Algorithm        = "simhash"
	AlgorithmVersion = "1.0"
	Vendor           = "JD"
)

// PreprocessorMap return PreProcessors info.
func PreprocessorMap() map[string]preprocessor.PreProcessor {
	return preprocessorMap
}

type result struct {
	path        string
	fingerprint model.FileFingerprint
	err         error
}

// Compare compares two text, returns the hamming distance.
func Compare(a string, b string) uint8 {
	fp1 := digester.EnhancedSimHash64([]byte(a))
	fp2 := digester.EnhancedSimHash64([]byte(b))
	dis, _ := DistanceHex(fp1, fp2)
	return dis
}

// Distance compares two fingerprints, returns the hamming distance
func Distance(a uint64, b uint64) uint8 {
	v := a ^ b
	var c uint8
	for c = 0; v != 0; c++ {
		v &= v - 1
	}
	return c
}

// DistanceHex compares two fingerprints, returns the hamming distance
func DistanceHex(a string, b string) (uint8, error) {
	value1, err1 := strconv.ParseUint(digester.EnhancedSimHash64([]byte(a)), 16, 64)
	if err1 != nil {
		return 0, fmt.Errorf("parse first fp error: %w", err1)
	}
	value2, err2 := strconv.ParseUint(digester.EnhancedSimHash64([]byte(b)), 16, 64)
	if err2 != nil {
		return 0, fmt.Errorf("parse second fp error: %w", err2)
	}
	return Distance(value1, value2), nil
}

// CalcFingerprint calculates the fingerprint of a file or directory
func CalcFingerprint(cfg *config.SourceConfig) (*model.Fingerprint, error) {
	enabledPreProcessors := GetPreProcessors(cfg.Language)
	preprocessorNames := util.SliceMap(enabledPreProcessors, func(p preprocessor.PreProcessor) string {
		return p.Name()
	})
	log.Infof("enabled language preprocessor: %s", strings.Join(preprocessorNames, ","))
	s, err := os.Stat(cfg.SrcPath)
	if err != nil {
		return nil, err
	}
	var fp *model.Fingerprint
	if s.IsDir() {
		fp, err = CalcDirectoryFingerprint(cfg, enabledPreProcessors)
	} else {
		fp, err = CalcFileFingerprint(cfg, enabledPreProcessors)
	}
	if err != nil {
		log.Errorf("calc fingerprint error: %s\n", err.Error())
		os.Exit(-1)
	}
	return fp, nil
}

// CalcDirectoryFingerprint calculates the fingerprint of a directory
func CalcDirectoryFingerprint(cfg *config.SourceConfig, processors []preprocessor.PreProcessor) (*model.Fingerprint, error) {
	done := make(chan struct{})
	defer close(done)

	pathChan, errChan := util.WalkFilesWithMatcher(cfg.SrcPath, done, cfg.IgnoreDirsSet(), getSuffixMatcher(processors))
	resultChan := make(chan result)

	parallelism := cfg.Parallelism
	var wg sync.WaitGroup
	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go func() {
			defer wg.Done()
			for path := range pathChan {
				fp, err := generateFileFingerprint(path, processors)
				if err != nil {
					continue
				}
				select {
				case resultChan <- result{path: path, fingerprint: *fp, err: err}:
				case <-done:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return processResult(cfg, resultChan, errChan)
}

func processResult(cfg *config.SourceConfig, resultChan chan result,
	errChan <-chan error) (*model.Fingerprint, error) {
	files := make([]model.FileFingerprint, 0)
	for r := range resultChan {
		if r.err != nil {
			return nil, r.err
		}
		r.fingerprint.File = strings.TrimPrefix(r.path, cfg.SrcPath)
		files = append(files, r.fingerprint)
	}
	if err := <-errChan; err != nil {
		return nil, err
	}
	util.SliceSort(files, func(i, j model.FileFingerprint) bool {
		return strings.Compare(i.File, j.File) < 0
	})
	totalFiles := len(files)
	var totalLines int64
	var totalSize int64
	for i := 0; i < totalFiles; i++ {
		totalLines += files[i].Lines
		totalSize += files[i].Size
	}

	fp := &model.Fingerprint{
		Metadata: model.Metadata{
			TotalFiles: int64(totalFiles),
			TotalCount: int64(totalFiles),
			TotalSize:  totalSize,
			TotalLines: totalLines,
			CreatedAt:  time.Now().UnixMilli(),
			Vendor:     vendor(),
		},
		Files: files,
	}
	return fp, nil
}

func getSuffixMatcher(processors []preprocessor.PreProcessor) *pattern_set.PatternSet {
	fileTypes := util.SliceFlatMap(processors, func(preprocessor preprocessor.PreProcessor) []string {
		return preprocessor.SupportedFileTypes()
	})
	if len(fileTypes) > 0 {
		return pattern_set.NewSuffixPatternMatchSet(fileTypes...)
	}
	return nil
}

// CalcFileFingerprint calculates the fingerprint of a file
func CalcFileFingerprint(cfg *config.SourceConfig, processors []preprocessor.PreProcessor) (*model.Fingerprint, error) {
	path := cfg.SrcPath

	fileFp, err := generateFileFingerprint(path, processors)
	if err != nil {
		return nil, err
	}
	fp := &model.Fingerprint{
		Metadata: model.Metadata{
			TotalFiles: 1,
			TotalCount: 1,
			TotalLines: fileFp.Lines,
			TotalSize:  fileFp.Size,
			Language:   []string{fileFp.Language},
			OutputMode: model.OutputSingleFile,
			CreatedAt:  time.Now().UnixMilli(),
			Vendor:     vendor(),
		},
		Files: []model.FileFingerprint{*fileFp},
	}
	return fp, nil
}

func generateFileFingerprint(path string, processors []preprocessor.PreProcessor) (*model.FileFingerprint, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file error: %w", err)
	}
	// find matched processor
	var processor preprocessor.PreProcessor

	for i := 0; i < len(processors); i++ {
		fileExt := filepath.Ext(path)
		if slices.Contains(processors[i].SupportedFileTypes(), fileExt) {
			processor = processors[i]
		}
	}
	if processor == nil {
		return nil, fmt.Errorf("cannot find matched processor for %s", path)
	}

	lines := len(util.SliceFilter(data, func(b byte) bool {
		return b == '\n'
	}))
	md5, _ := util.MD5Sum(bytes.NewReader(data))
	sha1, _ := util.SHA1Sum(bytes.NewReader(data))
	sha256, _ := util.SHA256Sum(bytes.NewReader(data))
	fp := &model.FileFingerprint{
		File:     path,
		Lines:    int64(lines),
		Size:     stat.Size(),
		MD5:      md5,
		SHA1:     sha1,
		SHA256:   sha256,
		Language: processor.Name(),
		Fingerprint: model.FingerprintValue{
			File: digester.EnhancedSimHash64([]byte(processor.ProcessContent(string(data)))),
		},
	}
	return fp, nil
}

func vendor() model.Vendor {
	return model.Vendor{
		Name:        Vendor,
		ToolName:    config.APPNAME,
		ToolVersion: config.VERSION,
		AlgoName:    Algorithm,
		AlgoVersion: AlgorithmVersion,
	}
}
