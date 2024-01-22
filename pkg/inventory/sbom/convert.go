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
	"fmt"
	"os"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

// ConvertSBOM converts a SBOM to another format
func ConvertSBOM(cfg *config.ConvertConfig) (*model.SBOM, error) {
	file, err := os.Open(cfg.Input)
	if err != nil {
		log.Errorf("open sbom file error: %s\n", err.Error())
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	var sbomFormat format.Format
	if len(cfg.Original) == 0 {
		sbomFormat, err = spec.DetectFormat(file)
		if err != nil {
			log.Errorf("load file error: %s\n", err.Error())
			return nil, err
		}
		if sbomFormat == nil {
			log.Errorf("unsupported file format")
			return nil, fmt.Errorf("unsupported file format")
		}
	} else {
		sbomFormat = spec.GetFormat(cfg.Original)
		if sbomFormat == nil {
			log.Errorf("unsupported file format")
			return nil, fmt.Errorf("unsupported file format")
		}
		err = sbomFormat.Load(file)
		if err != nil {
			log.Errorf("load sbom file error: %s\n", err.Error())
			return nil, err
		}
	}
	return sbomFormat.Spec().ToModel(), nil
}
