// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sbom

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/source"
	model3 "gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// AssemblySBOM assembles a SBOM from files
func AssemblySBOM(cfg *config.AssemblyConfig) (*model3.SBOM, error) {
	sourceFile := filepath.Join(cfg.Path, "source.json")
	packageFile := filepath.Join(cfg.Path, "package.json")
	artifactFile := filepath.Join(cfg.Path, "artifact.json")

	sourceInfo := &model3.Source{}
	_, err := os.Stat(sourceFile)
	if err == nil {
		err := loadJSONFile(sourceFile, sourceInfo)
		if err != nil {
			log.Errorf("load source info file error: %s\n", err.Error())
			return nil, err
		}
	} else if os.IsNotExist(err) {
		fp, err := loadFingerprint(cfg.Path)
		sourceInfo = source.ConvertFingerprint(fp)
		if err != nil {
			log.Errorf("load source info file error: %s\n", err.Error())
			return nil, err
		}
	} else {
		log.Errorf("load source info file error: %s\n", err.Error())
		return nil, fmt.Errorf("load source info file error")
	}

	artifactInfo := &model3.Artifact{}
	err = loadJSONFile(artifactFile, artifactInfo)
	if err != nil {
		log.Errorf("load artifact info file error: %s\n", err.Error())
		return nil, err
	}

	packageInfo := make([]model3.Package, 0)
	err = loadJSONFile(packageFile, &packageInfo)
	if err != nil {
		log.Errorf("load packages info file error: %s\n", err.Error())
		return nil, err
	}
	relationships := make([]model3.Relationship, len(packageInfo))
	for i := 0; i < len(packageInfo); i++ {
		relationships[i] = model3.Relationship{
			Type:    model3.DependencyOf,
			FromID:  fmt.Sprintf("Ref-%s-%s", artifactInfo.Name, artifactInfo.Version),
			ToID:    fmt.Sprintf("Ref-%s-%s", packageInfo[i].Name, packageInfo[i].Version),
			Comment: "",
		}
	}
	return &model3.SBOM{
		NamespaceURI:  cfg.NamespaceURI,
		Source:        *sourceInfo,
		Artifact:      *artifactInfo,
		Packages:      packageInfo,
		Relationships: relationships,
		CreationInfo: model3.CreationInfo{
			Creators: []model3.Creator{
				{Creator: config.AppNameVersion(), CreatorType: "Tool"},
				{Creator: artifactInfo.Supplier, CreatorType: "Organization"},
			},
		},
	}, nil
}

func loadJSONFile(path string, obj interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file error: %w", err)
	}
	return json.Unmarshal(data, obj)
}

func loadFingerprint(path string) (*model.Fingerprint, error) {
	fingerprintFile := filepath.Join(path, "fingerprint.json")
	metadataFile := filepath.Join(path, "fingerprint", "metadata.json")
	filesPath := filepath.Join(path, "fingerprint", "files")
	fp := &model.Fingerprint{}

	_, err := os.Stat(fingerprintFile)
	if err == nil {
		err := loadJSONFile(fingerprintFile, fp)
		if err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		_, err := os.Stat(metadataFile)
		if err != nil {
			return nil, fmt.Errorf("metadata file invalid: %w", err)
		}
		err = loadJSONFile(fingerprintFile, fp)
		if err != nil {
			return nil, err
		}
		if fp.Metadata.OutputMode == model.OutputMultiFile {
			files, err := loadMultiFiles(filesPath)
			if err != nil {
				return nil, fmt.Errorf("walk dir error: %w", err)
			}
			fp.Files = files
		}
	} else {
		return nil, fmt.Errorf("fingerprint file invalid: %w", err)
	}
	return fp, nil
}

func loadMultiFiles(filesPath string) ([]model.FileFingerprint, error) {
	files := make([]model.FileFingerprint, 0)
	err := filepath.WalkDir(filesPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filesPath == path {
			return nil
		}
		if entry.IsDir() {
			return filepath.SkipDir
		}
		ffp := model.FileFingerprint{}
		err1 := loadJSONFile(path, ffp)
		if err1 != nil {
			return err1
		}
		files = append(files, ffp)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk dir error: %w", err)
	}
	return files, nil
}
