// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format/spdx"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format/xspdx"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
)

const _SEP = format.SEP

func AllSpecifications() []format.Specification {
	return []format.Specification{
		xspdx.NewSpecification(),
		spdx.NewSpecification(),
	}
}

// AllFormats returns all sbom formats
func AllFormats() []format.Format {
	formats := make([]format.Format, 0)
	for _, s := range AllSpecifications() {
		formats = append(formats, s.Formats()...)
	}
	return formats
}

// AllFormatNames returns all sbom format names
func AllFormatNames() []string {
	return util.SliceMap(AllFormats(), func(f format.Format) string {
		return f.Spec().Name() + _SEP + f.Type()
	})
}

func AllUpdaterDesc() map[string]string {
	specs := AllSpecifications()
	descs := make(map[string]string)
	for _, s := range specs {
		for _, updater := range s.Updaters() {
			d := updater.Desc() + " (for " + s.Name() + ")"
			desc, ok := descs[updater.Name()]
			if ok {
				desc += "; " + d
			} else {
				desc = d
			}
			descs[updater.Name()] = desc
		}
	}
	return descs
}

const count = 2

// GetFormat returns a sbom format by spec name and format type
func GetFormat(name string) format.Format {
	name = strings.TrimSpace(name)
	segs := strings.SplitN(name, _SEP, count)
	if len(segs) != 2 {
		return nil
	}
	specName := segs[0]
	formatType := segs[1]
	for _, s := range AllSpecifications() {
		if s.Name() == specName {
			for _, f := range s.Formats() {
				if f.Type() == formatType {
					return f
				}
			}
		}
	}
	return nil
}

// DetectFormat detects a sbom format by reader, load and validate has no error
func DetectFormat(reader io.Reader) (format.Format, error) {
	formats := AllFormats()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}
	for i := 0; i < len(formats); i++ {
		r := bytes.NewReader(data)
		if formats[i].Load(r) == nil && formats[i].Spec().Validate() == nil {
			return formats[i], nil
		}
	}
	return nil, errors.New("not supported file format")
}
