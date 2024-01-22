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
	"fmt"
	"io"

	"github.com/spdx/tools-golang/tagvalue"

	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format"
)

// TagValueFormat is the tagvalue format of spdx
type TagValueFormat struct {
	spec *Spec
}

func (f *TagValueFormat) Spec() format.Specification {
	return f.spec
}

func (f *TagValueFormat) Load(reader io.Reader) error {
	doc, err := tagvalue.Read(reader)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}
	f.spec.doc = doc
	return nil
}

func (f *TagValueFormat) Dump(writer io.Writer) error {
	err := tagvalue.Write(f.spec.doc, writer)
	if err != nil {
		return fmt.Errorf("dump error: %w", err)
	}
	return nil
}

func (f *TagValueFormat) Type() string {
	return "tagvalue"
}
