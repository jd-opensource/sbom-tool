// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package util

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/pattern_set"
)

// WalkFilesWithMatcher walks the file tree rooted at path, sending the paths of all regular files to pathChan.
// If ignoreMatcher is not nil, files matching the ignoreMatcher will be ignored.
// If hitMatcher is not nil, only files matching the hitMatcher will be sent to pathChan.
// If an error is encountered, it will be sent to errChan. If doneChan is closed, the walk process will be canceled.
func WalkFilesWithMatcher(path string, doneChan <-chan struct{}, ignoreMatcher *pattern_set.PatternSet, hitMatcher *pattern_set.PatternSet) (<-chan string, <-chan error) {
	pathChan := make(chan string)
	errChan := make(chan error, 1)

	go func() {
		defer close(pathChan)
		errChan <- filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}

			if ignoreMatcher != nil && ignoreMatcher.Match(file) {
				return nil
			}
			if hitMatcher != nil && !hitMatcher.Match(file) {
				return nil
			}
			select {
			case pathChan <- file:
			case <-doneChan:
				return errors.New("process canceled")
			}
			return nil
		})
	}()
	return pathChan, errChan
}

// WriteToJSONFile writes the obj to a json file
func WriteToJSONFile(path string, obj interface{}) error {
	if len(path) == 0 {
		path = "artifact.json"
	}
	file, err := os.Create(path)
	if err != nil {
		log.Errorf("create file error: %s", err.Error())
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	data, err := json.Marshal(obj)
	if err != nil {
		log.Errorf("marshal error: %s", err.Error())
		return err
	}
	_, err = file.Write(data)
	if err != nil {
		log.Errorf("save file error: %s", err.Error())
		return err
	}
	return nil
}

// PathExists check if the path exists
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
