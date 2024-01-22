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
	"github.com/anchore/packageurl-go"
	"go.uber.org/zap/zapcore"
)

// PkgType is the type of package
type PkgType = string

var (
	PkgTypeGeneric   PkgType = packageurl.TypeGeneric
	PkgTypeCargo     PkgType = packageurl.TypeCargo
	PkgTypeCocoapods PkgType = packageurl.TypeCocoapods
	PkgTypeComposer  PkgType = packageurl.TypeComposer
	PkgTypeConan     PkgType = packageurl.TypeConan
	PkgTypeConda     PkgType = packageurl.TypeConda
	PkgTypeGem       PkgType = packageurl.TypeGem
	PkgTypeGolang    PkgType = packageurl.TypeGolang
	PkgTypeMaven     PkgType = packageurl.TypeMaven
	PkgTypeNPM       PkgType = packageurl.TypeNPM
	PkgTypeNuget     PkgType = packageurl.TypeNuget
	PkgTypePub       PkgType = packageurl.TypePub
	PkgTypePyPi      PkgType = packageurl.TypePyPi
	PkgTypeRPM       PkgType = packageurl.TypeRPM
	PkgTypeDEB       PkgType = packageurl.TypeDebian
	PkgTypeSwift     PkgType = packageurl.TypeSwift
	PkgTypeDylib     PkgType = "dylib"
	PkgTypeCarthage  PkgType = "carthage"
	PkgTypeBower     PkgType = "bower"
	PkgTypeLua       PkgType = "lua"
)

// Package is the info of a package
type Package struct {
	Name             string   `json:"name"` // required
	Version          string   `json:"version"`
	Type             PkgType  `json:"type"` // required
	PURL             string   `json:"purl"` // required, the Package URL (see https://github.com/package-url/purl-spec)
	Supplier         string   `json:"supplier"`
	FilesAnalyzed    bool     `json:"filesAnalyzed"`
	VerificationCode string   `json:"verificationCode"`
	LicenseConcluded []string `json:"licenseConcluded"`
	LicenseDeclared  []string `json:"licenseDeclared"`
	Dependencies     []string `json:"dependencies"` // purl of dependencies
	SourceLocation   string   `json:"sourceLocation"`
}

func (p *Package) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", p.Name)
	enc.AddString("type", p.Type)
	enc.AddString("version", p.Version)
	return nil
}

// PackageEqual returns true if p1 and p2 are equal
func PackageEqual(p1, p2 *Package) bool {
	return p1.Name == p2.Name && p1.Version == p2.Version
}
