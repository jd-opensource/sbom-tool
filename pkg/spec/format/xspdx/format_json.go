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
	"fmt"
	"io"

	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format"
	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format/xspdx/model/json"
)

// JSONFormat is the json format of xspdx
type JSONFormat struct {
	spec *Spec
}

func (f *JSONFormat) Spec() format.Specification {
	return f.spec
}

func (f *JSONFormat) Load(reader io.Reader) error {
	doc, err := json.Read(reader)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}
	f.spec.doc = doc
	return nil
}

func (f *JSONFormat) Dump(writer io.Writer) error {
	err := json.Write(*f.spec.doc, writer)
	if err != nil {
		return fmt.Errorf("dump error: %w", err)
	}
	return nil
}

func (f *JSONFormat) Type() string {
	return "json"
}
