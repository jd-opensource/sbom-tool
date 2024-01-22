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

// PomParent contains the fields within the <parent> tag in a pom.xml file
type PomParent struct {
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
	Version    string `json:"version"`
}

// PomProperties represents the fields of interest extracted from a Java archive's pom.properties file.
type PomProperties struct {
	Path       string            `mapstructure:"path" json:"path"`
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"groupId" `
	ArtifactID string            `mapstructure:"artifactId" json:"artifactId" `
	Version    string            `mapstructure:"version" json:"version"`
	Extra      map[string]string `mapstructure:",remain" json:"extraFields,omitempty"`
}

// PomProject represents fields of interest extracted from a Java archive's pom.xml file. See https://maven.apache.org/ref/3.6.3/maven-model/maven.html for more details.
type PomProject struct {
	Path         string          `json:"path"`
	Parent       *PomParent      `json:"parent,omitempty"`
	GroupID      string          `json:"groupId"`
	ArtifactID   string          `json:"artifactId"`
	Version      string          `json:"version"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	URL          string          `json:"url,omitempty"`
	Licenses     []string        `json:"licenses,omitempty"`
	Dependencies []PomDependency `json:"dependencies,omitempty"`
}

type PomDependency struct {
	GroupID    string
	ArtifactID string
	Version    string
}
