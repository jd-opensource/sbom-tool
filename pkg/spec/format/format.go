// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package format

import (
	"io"
)

// Format is a sbom file format
type Format interface {
	Spec() Specification         // Specification returns the spec of this format
	Type() string                // Type returns the format type
	Load(reader io.Reader) error // Load loads a sbom from reader
	Dump(writer io.Writer) error // Dump dumps a sbom to writer
}

// FormatName returns a sbom format full name
func FormatName(f Format) string {
	if f == nil {
		return ""
	}
	return f.Spec().Name() + SEP + f.Type()
}
