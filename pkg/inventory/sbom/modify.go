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
	"os"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
)

func ModifySBOM(cfg *config.ModifyConfig) (format.Format, error) {
	sbomFormat := spec.GetFormat(cfg.Format)

	file, err := os.Open(cfg.Input)
	if err != nil {
		log.Errorf("open sbom file error: %s\n", err.Error())
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	err = sbomFormat.Load(file)
	if err != nil {
		log.Errorf("load sbom file error: %s\n", err.Error())
		return nil, err
	}

	updaters := sbomFormat.Spec().Updaters()

	if len(cfg.Update) > 0 && len(updaters) > 0 {
		for _, updater := range updaters {
			values := cfg.Update[updater.Name()]
			for _, v := range *values {
				err := updater.Update(v)
				if err != nil {
					log.Errorf("update document error: %s", err.Error())
					return nil, err
				}
			}
		}
	}
	return sbomFormat, nil
}
