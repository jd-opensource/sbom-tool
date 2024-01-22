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
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

const SEP = "-"

// Specification is a sbom specfication
type Specification interface {
	Name() string             // Name returns the spec name
	Version() string          // Version returns the spec version
	Metadata() model.Metadata // Metadata returns the metadata,e.g. creator / tool / created
	Validate() error          // Validate validates the spec
	Formats() []Format        // Formats returns all formats of this spec
	FromModel(*model.SBOM)    // FromModel converts a SBOM model to spec
	ToModel() *model.SBOM     // ToModel converts spec to a SBOM model
	Updaters() []Updater
}
