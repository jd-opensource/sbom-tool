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

import "go.uber.org/zap/zapcore"

// RelationType is the type of relation
type RelationType string

const (
	DependencyOf RelationType = "DependencyOf" // Is to be used when SPDXRef-A is dependency of SPDXRef-B.	A is explicitly stated as a dependency of B in a machine-readable file. Use when a package manager does not define scopes.
)

// A Relationship is a relationship between two elements of sbom.
type Relationship struct {
	Type    RelationType `json:"type"` // see sbom.RelationType
	FromID  string       `json:"from"`
	ToID    string       `json:"to"`
	Comment string       `json:"comment,omitempty"`
}

func (r *Relationship) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("type", string(r.Type))
	enc.AddString("from", r.FromID)
	enc.AddString("to", r.ToID)
	return nil
}
