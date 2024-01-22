// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package xspdx

import (
	"errors"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format"
	xspdxModel "gitee.com/JD-opensource/sbom-tool/pkg/spec/format/xspdx/model"
)

var ErrDocumentEmpty = errors.New("document is empty")
var ErrSourceEmpty = errors.New("source property is empty")
var ErrArtifactEmpty = errors.New("artifact property is empty")

// Spec is the xspdx specification
type Spec struct {
	doc      *xspdxModel.XSPDXDocument
	formats  []format.Format
	updaters []format.Updater
}

func NewSpecification() format.Specification {
	s := &Spec{}
	s.formats = []format.Format{
		&JSONFormat{spec: s},
	}
	s.updaters = newSpecUpdaters(s)
	return s
}

func (s *Spec) Name() string {
	return "xspdx"
}

func (s *Spec) Version() string {
	return "1.0"
}

func (s *Spec) Formats() []format.Format {
	return s.formats
}

func (s *Spec) Validate() error {
	if s.doc == nil {
		return ErrDocumentEmpty
	}
	if s.doc.Source == nil {
		return ErrSourceEmpty
	}
	if s.doc.Artifact == nil {
		return ErrArtifactEmpty
	}
	return nil
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
