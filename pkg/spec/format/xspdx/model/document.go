// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package model

import (
	"encoding/json"
	"fmt"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type XSPDXDocument struct {
	*v2_3.Document
	Source   *Source   `json:"source"`
	Artifact *Artifact `json:"artifact"`
}

func (d *XSPDXDocument) UnmarshalJSON(b []byte) error {
	doc := v2_3.Document{}

	type Extra struct {
		Source   *Source   `json:"source"`
		Artifact *Artifact `json:"artifact"`
	}

	extra := Extra{}

	if err := json.Unmarshal(b, &doc); err != nil {
		fmt.Printf("unmarshal document err: %+v", err)
		return err
	}

	if err := json.Unmarshal(b, &extra); err != nil {
		fmt.Printf("unmarshal document err: %+v", err)
		return err
	}

	d.Document = &doc
	d.Source = extra.Source
	d.Artifact = extra.Artifact

	return nil
}
