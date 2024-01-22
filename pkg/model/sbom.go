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

type Metadata map[string]string

// SBOM represents the software bill of materials
type SBOM struct {
	NamespaceURI  string
	Source        Source         `json:"source"`
	Artifact      Artifact       `json:"artifact"`
	Packages      []Package      `json:"packages"`
	Relationships []Relationship `json:"relationships"`
	CreationInfo  CreationInfo   `json:"creationInfo"`
}

// CreationInfo represents the creation info of the SBOM
type CreationInfo struct {
	Creators       []Creator `json:"creators"`
	Created        string    `json:"created"`
	CreatorComment string    `json:"creatorComment"`
}

// Creator represents the creator of the SBOM
type Creator struct {
	Creator     string `json:"creator"`     // name, email, domain
	CreatorType string `json:"creatorType"` // Person, Organization, Tool
}
