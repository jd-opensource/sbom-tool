// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package spdx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spdx/tools-golang/spdx/v2/common"

	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

var ErrDocumentInvalid = errors.New("document invalid")

func newSpecUpdaters(s *Spec) []format.Updater {
	return []format.Updater{
		newAddCreatorUpdater(s),
	}
}

func newAddCreatorUpdater(s *Spec) format.Updater {
	exp, err := json.Marshal(common.Creator{Creator: "Tim (tim@demo.com)", CreatorType: "Person"})
	if err != nil {
		log.Warnf("example error: %w", err)
	}
	desc := "add creator of document, example: '" + string(exp) + "'"
	return format.NewUpdater("add-creator", desc, func(value string) error {
		if s == nil || s.doc == nil || s.doc.CreationInfo == nil {
			return ErrDocumentInvalid
		}
		creator := common.Creator{}
		err := json.Unmarshal([]byte(value), &creator)
		if err != nil {
			return fmt.Errorf("parse input error: %w", err)
		}
		s.doc.CreationInfo.Creators = append(s.doc.CreationInfo.Creators, creator)
		return nil
	})
}
