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
	"errors"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format"
)

var ErrDocumentEmpty = errors.New("document empty")

// Spec is the specification os SPDX
// see https://spdx.github.io/spdx-spec/
type Spec struct {
	doc      *spdx.Document
	formats  []format.Format
	updaters []format.Updater
}

func NewSpecification() format.Specification {
	s := &Spec{}
	s.formats = []format.Format{
		&JSONFormat{spec: s},
		&TagValueFormat{spec: s},
	}
	s.updaters = newSpecUpdaters(s)
	return s
}

func (s *Spec) Name() string {
	return "spdx"
}

func (s *Spec) Version() string {
	return spdx.Version
}

func (s *Spec) Formats() []format.Format {
	return s.formats
}

func (s *Spec) Validate() error {
	if s.doc == nil {
		return ErrDocumentEmpty
	}
	return spdxlib.ValidateDocument(s.doc)
}

func (s *Spec) Metadata() model.Metadata {
	meta := make(map[string]string)
	if s.doc != nil {
		meta["SPDXVersion"] = s.doc.SPDXVersion
		meta["DataLicense"] = s.doc.DataLicense
		if s.doc.CreationInfo != nil {
			meta["CreatedAt"] = s.doc.CreationInfo.Created
			for i := 0; i < len(s.doc.CreationInfo.Creators); i++ {
				c := s.doc.CreationInfo.Creators[i]
				meta[c.CreatorType] = c.Creator
			}
		}
	}
	return meta
}

func (s *Spec) Updaters() []format.Updater {
	return s.updaters
}
