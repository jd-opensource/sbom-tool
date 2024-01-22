// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package mvn

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/mitchellh/mapstructure"

	"gitee.com/jd-opensource/sbom-tool/pkg/util/ziputil"
)

const (
	pomPropertiesGlob = "*pom.properties"
	pomXMLGlob        = "*pom.xml"
)

func PomPropertiesByParentPath(archivePath string) (map[string]PomProperties, error) {
	manifest, err := ziputil.ResolveFileManifest(archivePath)
	if err != nil {
		return nil, err
	}
	extractPaths := manifest.GlobMatch(pomPropertiesGlob)

	contentsOfMavenPropertiesFiles, err := ziputil.GetLinesFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	propertiesByParentPath := make(map[string]PomProperties)
	for filePath, fileContents := range contentsOfMavenPropertiesFiles {
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			// log.WithFields("contents-path", filePath, "location", location.AccessPath()).Warnf("failed to parse pom.properties: %+v", err)
			continue
		}

		if pomProperties == nil {
			continue
		}

		if pomProperties.Version == "" || pomProperties.ArtifactID == "" {
			// TODO: if there is no parentPkg (no maven manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		propertiesByParentPath[path.Dir(filePath)] = *pomProperties
	}

	return propertiesByParentPath, nil
}

func PomProjectByParentPath(archivePath string) (map[string]PomProject, error) {
	manifest, err := ziputil.ResolveFileManifest(archivePath)
	if err != nil {
		return nil, err
	}
	extractPaths := manifest.GlobMatch(pomXMLGlob)
	contentsOfMavenProjectFiles, err := ziputil.GetLinesFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	projectByParentPath := make(map[string]PomProject)
	for filePath, fileContents := range contentsOfMavenProjectFiles {
		pomProject, err := parsePomXMLProject(filePath, strings.NewReader(fileContents))
		if err != nil {
			// log.WithFields("contents-path", filePath, "location", location.AccessPath()).Warnf("failed to parse pom.xml: %+v", err)
			continue
		}

		if pomProject == nil {
			continue
		}

		// 如果子项目的依赖没有声明版本号（没写）那就默认继承父项目的版本号，如果写了版本号就使用自己的版本
		if pomProject.Version == "" && pomProject.Parent != nil {
			pomProject.Version = pomProject.Parent.Version
		}

		if pomProject.Version == "" || pomProject.ArtifactID == "" {
			// TODO: if there is no parentPkg (no maven manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		projectByParentPath[path.Dir(filePath)] = *pomProject
	}
	return projectByParentPath, nil
}

func parsePomProperties(path string, reader io.Reader) (*PomProperties, error) {
	var props PomProperties
	propMap := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore empty lines and comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimLeft(line, " "), "#") {
			continue
		}

		idx := strings.IndexAny(line, "=:")
		if idx == -1 {
			return nil, fmt.Errorf("unable to split pom.properties key-value pairs: %q", line)
		}

		key := strings.TrimSpace(line[0:idx])
		value := strings.TrimSpace(line[idx+1:])
		propMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read pom.properties: %w", err)
	}

	if err := mapstructure.Decode(propMap, &props); err != nil {
		return nil, fmt.Errorf("unable to parse pom.properties: %w", err)
	}

	props.Path = path

	return &props, nil
}
