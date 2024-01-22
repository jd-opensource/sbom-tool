// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sbom

import (
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/config"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/artifact"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/deb"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/rpm"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/source"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec"
	"gitee.com/JD-opensource/sbom-tool/pkg/spec/format/xspdx"
	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
)

const SourcePhase = "source"
const PackagePhase = "package"
const ArtifactPhase = "artifact"

var allPhases = []string{SourcePhase, PackagePhase, ArtifactPhase}

// GenerateSBOM generates a SBOM
func GenerateSBOM(cfg *config.GenerateConfig) (*model.SBOM, error) {

	phases := getEnabledPhases(cfg.SkipPhases)

	sbomDoc := &model.SBOM{
		NamespaceURI: cfg.NamespaceURI,
		// Relationships: relations,
		CreationInfo: model.CreationInfo{
			Creators: []model.Creator{
				{Creator: config.AppNameVersion(), CreatorType: "Tool"},
				{Creator: cfg.PackageSupplier, CreatorType: "Organization"},
			},
		},
	}
	sbomFormat := spec.GetFormat(cfg.Format)
	if sbomFormat == nil {
		return nil, fmt.Errorf("invalid format: %s", cfg.Format)
	}

	if slices.Contains(phases, SourcePhase) && sbomFormat.Spec().Name() == xspdx.NewSpecification().Name() {
		sourceInfo, err := source.GetSourceInfo(&cfg.SourceConfig)
		if err != nil {
			log.Errorf("collect source error: %s", err.Error())
		}
		sbomDoc.Source = *sourceInfo
	}
	if slices.Contains(phases, PackagePhase) {
		cm := pckg.NewCollectorManager(&cfg.PackageConfig)
		packages, err := cm.Collect(cfg.Path)
		if err != nil {
			log.Errorf("collect packages error: %s", err.Error())
			return nil, err
		}
		sbomDoc.Packages = packages
	}
	if slices.Contains(phases, ArtifactPhase) {
		artifactInfo, err := artifact.Collect(&cfg.ArtifactConfig, cfg.Path)
		if err != nil {
			log.Errorf("collect artifact error: %s", err.Error())
			return nil, err
		}
		sbomDoc.Artifact = *artifactInfo
	} else {
		sbomDoc.Artifact = model.Artifact{
			Package: *artifact.ArtifactPackage(&cfg.ArtifactConfig),
		}
	}

	//package内主包相关的license需要增加给Artifact包
	if len(sbomDoc.Artifact.LicenseDeclared) == 0 {
		for _, p := range sbomDoc.Packages {
			if p.Name == sbomDoc.Artifact.Name && p.Type != packageurl.TypeGeneric && len(p.LicenseDeclared) > 0 {
				sbomDoc.Artifact.LicenseDeclared = p.LicenseDeclared
			}
		}
	}

	return sbomDoc, nil
}

// GenerateComponentSBOM generates a SBOM from a component
func GenerateComponentSBOM(cfg *config.GenerateConfig) (*model.SBOM, error) {
	sbomDoc := &model.SBOM{
		NamespaceURI: cfg.NamespaceURI,
		// Relationships: relations,
		CreationInfo: model.CreationInfo{
			Creators: []model.Creator{
				{Creator: config.AppNameVersion(), CreatorType: "Tool"},
				{Creator: cfg.PackageSupplier, CreatorType: "Organization"},
			},
		},
	}

	if len(cfg.SrcPath) > 0 {
		sourceInfo, err := source.GetSourceInfo(&cfg.SourceConfig)
		if err != nil {
			log.Errorf("collect source error: %s", err.Error())
		}
		sbomDoc.Source = *sourceInfo
	}
	packageConfig := config.PackageConfig{
		Path: cfg.DistPath,
		Collectors: strings.Join([]string{
			rpm.Name(),
			deb.Name(),
		}, ","),
	}
	cm := pckg.NewCollectorManager(&packageConfig)
	packages, err := cm.Collect(cfg.DistPath)
	if err != nil {
		log.Errorf("collect packages error: %s", err.Error())
		return nil, err
	}
	sbomDoc.Packages = packages

	artifactInfo, err := artifact.Collect(&cfg.ArtifactConfig, cfg.Path)
	if err != nil {
		log.Errorf("collect artifact error: %s", err.Error())
		return nil, err
	}
	sbomDoc.Artifact = *artifactInfo

	rootPackage := getRootPackage(packages)
	if rootPackage != nil {
		if artifactInfo.Name == "" {
			artifactInfo.Package = *rootPackage
		}
		if artifactInfo.Supplier == "" {
			artifactInfo.Supplier = rootPackage.Supplier
		}
	}
	sbomDoc.Artifact = *artifactInfo
	return sbomDoc, nil
}

func getEnabledPhases(skipPhases string) []string {
	items := strings.Split(skipPhases, ",")
	return util.SliceFilter(allPhases, func(s string) bool {
		return !slices.Contains(items, s)
	})
}

func getRootPackage(pkgs []model.Package) *model.Package {
	deps := make(map[string]struct{})
	for _, pkg := range pkgs {
		for _, dep := range pkg.Dependencies {
			deps[dep] = struct{}{}
		}
	}
	ps := util.SliceFilter(pkgs, func(p model.Package) bool {
		_, ok := deps[p.PURL]
		return !ok
	})
	if len(ps) == 1 {
		return &ps[0]
	}
	return nil
}
