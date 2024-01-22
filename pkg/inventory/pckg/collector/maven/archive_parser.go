// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/maven/archive"
	"gitee.com/JD-opensource/sbom-tool/pkg/inventory/pckg/collector/maven/mvn"
	"gitee.com/JD-opensource/sbom-tool/pkg/model"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/license"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/ziputil"
)

var archiveFormats = []string{"**/*.jar", "**/*.war"}
var sbomArchiveTempFirstDirPrefixName = "sbom-archive-"
var sbomArchiveTempSecondDirName = "items"

// ArchiveParser is a parser for maven archive files
type ArchiveParser struct {
	Embedded bool
}

// NewArchiveParser returns a new ArchiveParser
func NewArchiveParser() *ArchiveParser {
	return &ArchiveParser{}
}

func (m *ArchiveParser) Matcher() collector.FileMatcher {
	return &collector.FilePatternMatcher{Patterns: []string{"*.jar"}}
}

func (m *ArchiveParser) Parse(path string) ([]model.Package, error) {
	var pkgs []model.Package

	log.Infof("parse path: " + path)

	// 解析META-INF/manifest.mf和文件名
	log.Debugf("parse content")

	mainPkg, err := archive.DiscoverMainPackage(path)
	if err != nil {
		return nil, err
	}

	// 解析pom.properties和pom.xml
	log.Debugf("parse pom.properties and pom.xml")
	pomPackages, err := discoverPackagesFromPomFiles(path, m.Embedded)
	if err != nil {
		return nil, err
	}

	for _, pomPackage := range pomPackages {
		artifactId := pomPackage.Name
		segs := strings.Split(artifactId, "/")
		if len(segs) > 1 {
			artifactId = segs[1]
		}
		mainVersion := mainPkg.Version
		mainSegs := strings.Split(mainVersion, "-")
		pomVersion := pomPackage.Version
		// match common@1.0.0-SNAPSHOT and common@1.0.0-20230914.062300-3
		if strings.HasSuffix(pomPackage.Version, "-SNAPSHOT") && len(mainSegs) > 2 {
			pomVersion = pomVersion[:len(pomVersion)-9]
			mainVersion = strings.Join(mainSegs[:len(mainSegs)-2], "-")
		}
		if artifactId == mainPkg.Name && pomVersion == mainVersion {
			mainPkg.Name = pomPackage.Name
			mainPkg.PURL = packageURL(mainPkg.Name, mainPkg.Version, "")
			if len(pomPackage.LicenseDeclared) > 0 {
				mainPkg.LicenseDeclared = pomPackage.LicenseDeclared
			}
			continue
		} else {
			pkgs = append(pkgs, pomPackage)
		}
	}

	if mainPkg.PURL == "" {
		mainPkg.PURL = packageURL(mainPkg.Name, mainPkg.Version, "")
	}

	// mainPkg放入Pkg列表
	pkgs = append(pkgs, *mainPkg)

	// 解析内嵌的归档文件
	log.Debugf("parse nested archive files")
	nestedPkgs, _ := discoverPackagesFromArchiveFiles(path)
	if len(nestedPkgs) > 0 {
		nestedPkgs = modifyNestedPkgSourcePath(mainPkg, nestedPkgs)
		pkgs = append(pkgs, nestedPkgs...)
	}
	pkgs = collector.SortPackage(pkgs)
	return pkgs, nil
}

func modifyNestedPkgSourcePath(mainPkg *model.Package, nestedPkgs []model.Package) []model.Package {
	for i, pkg := range nestedPkgs {
		if strings.Contains(pkg.SourceLocation, sbomArchiveTempFirstDirPrefixName) && strings.Contains(pkg.SourceLocation, sbomArchiveTempSecondDirName) {
			location := strings.Split(pkg.SourceLocation, "/"+sbomArchiveTempSecondDirName)[1]
			nestedPkgs[i].SourceLocation = mainPkg.SourceLocation + "!" + pkgNameRemoveEndTimestamp(location)
		}
	}
	return nestedPkgs
}

func discoverPackagesFromArchiveFiles(archivePath string) ([]model.Package, error) {
	var pkgs []model.Package
	tempDir, err := os.MkdirTemp("", sbomArchiveTempFirstDirPrefixName)
	if err != nil {
		return pkgs, nil
	}
	itemsDir := filepath.Join(tempDir, sbomArchiveTempSecondDirName)
	_ = os.Mkdir(itemsDir, 0o755)
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(itemsDir)

	items, err := PickArchiveFilesToUniqueTempFile(archivePath, itemsDir)
	if err == nil && len(items) > 0 {
		for _, item := range items {
			ap := NewArchiveParser()
			ap.Embedded = true
			subPkgs, _ := ap.Parse(item)
			pkgs = append(pkgs, subPkgs...)
		}
	}
	return pkgs, nil
}

func PickArchiveFilesToUniqueTempFile(archivePath, dir string) (map[string]string, error) {
	manifest, err := ziputil.ResolveFileManifest(archivePath)
	if err != nil {
		return nil, err
	}
	paths := manifest.GlobMatch(archiveFormats...)
	pickedFiles := make(map[string]string)

	if len(paths) == 0 {
		return pickedFiles, nil
	}

	visitor := func(file *zip.File) error {
		prefix := filepath.Base(filepath.Clean(file.Name)) + "-"

		tempFile, err := os.CreateTemp(dir, prefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		defer func(tempFile *os.File) {
			_ = tempFile.Close()
		}(tempFile)

		zipFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
		defer func() {
			err := zipFile.Close()
			if err != nil {
				log.Warnf("unable to close source file=%q from zip=%q: %+v", file.Name, archivePath, err)
			}
		}()

		if file.FileInfo().IsDir() {
			return fmt.Errorf("can not be directories, only files: %s", file.Name)
		}

		if err := ziputil.SafeCopy(tempFile, zipFile); err != nil {
			return fmt.Errorf("unable to copy to temp file for zip=%q: %w", archivePath, err)
		}

		pickedFiles[file.Name] = tempFile.Name()

		return nil
	}

	return pickedFiles, ziputil.TraverseFilesInZip(archivePath, visitor, paths...)
}

func discoverPackagesFromPomFiles(archivePath string, embedded bool) ([]model.Package, error) {
	var pkgs []model.Package
	// pom.properties
	properties, err := mvn.PomPropertiesByParentPath(archivePath)
	if err != nil {
		return nil, err
	}

	// pom.xml
	projects, err := mvn.PomProjectByParentPath(archivePath)
	if err != nil {
		return nil, err
	}
	hasProps := map[string]struct{}{}
	for parentPath, propertiesObj := range properties {
		hasProps[parentPath] = struct{}{}
		var pomProject *mvn.PomProject
		if proj, exists := projects[parentPath]; exists {
			pomProject = &proj
		}

		pkgFromPom := newPackageFromMavenData(propertiesObj, pomProject, archivePath)
		if pkgFromPom != nil {
			pkgs = append(pkgs, *pkgFromPom)
		}
		if !embedded && pomProject != nil {
			for _, dep := range pomProject.Dependencies {
				p := newPackage(dep.GroupID, dep.ArtifactID, dep.Version, archivePath)
				if p != nil {
					pkgs = append(pkgs, *p)
				}
			}
		}
	}
	for parentPath, projectObj := range projects {
		if _, ok := hasProps[parentPath]; ok {
			continue
		}
		pkg := newPackage(projectObj.GroupID, projectObj.ArtifactID, projectObj.Version, archivePath)
		if pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
		if !embedded {
			for _, dep := range projectObj.Dependencies {
				p := newPackage(dep.GroupID, dep.ArtifactID, dep.Version, archivePath)
				if p != nil {
					pkgs = append(pkgs, *p)
				}
			}
		}
	}
	return pkgs, nil
}

func newPackageFromMavenData(pomProperties mvn.PomProperties, pomProject *mvn.PomProject, archivePath string) *model.Package {
	licenses := make([]string, 0)
	if pomProject != nil && len(pomProject.Licenses) > 0 {
		for _, lic := range pomProject.Licenses {
			value, _, _ := license.ParseLicenseName(lic)
			if value != "" {
				licenses = license.SplitLicense(value, licenses)
			}
		}
	}
	groupId := trim(pomProperties.GroupID)
	artifactId := trim(pomProperties.ArtifactID)
	version := trim(pomProperties.Version)

	p := newPackage(groupId, artifactId, version, archivePath)
	if p != nil {
		p.LicenseDeclared = license.UniqueStrings(licenses)
	}
	return p
}
