// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package conan

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/license"
)

type testitem struct {
	title    string
	content  string
	expected []model.Package
}

var conanfileTestdata = []testitem{
	{
		title: "Normal",
		content: `
[requires]
zlib/1.2.11
base64/0.4.0

[tool_requires]
cmake/3.19.8

[generators]
CMakeDeps
CMakeToolchain
		`,
		expected: []model.Package{
			{
				Name:            "zlib",
				Version:         "1.2.11",
				Type:            model.PkgTypeConan,
				LicenseDeclared: []string{license.NOASSERTION_LICENSE},
			},
			{
				Name:            "base64",
				Version:         "0.4.0",
				Type:            model.PkgTypeConan,
				LicenseDeclared: []string{license.NOASSERTION_LICENSE},
			},
		},
	},
}

var conanlockTestdata = []testitem{
	{
		title: "Normal",
		content: `
		{
			"version": "0.5",
			"requires": [
				"zlib/1.2.11#ffa77daf83a57094149707928bdce823%1667396813.184",
				"base64/0.4.0#ac9bfd081aa5a0e6c6310489c46b7141%1664175644.582"
			],
			"build_requires": [],
			"python_requires": []
		}
		`,
		expected: []model.Package{
			{Name: "zlib", Version: "1.2.11", Type: model.PkgTypeConan},
			{Name: "base64", Version: "0.4.0", Type: model.PkgTypeConan},
		},
	},
}

var conanGraphTestData = []testitem{
	{
		title: "Normal",
		content: `
{
  "graph": {
    "nodes": {
      "0": {
        "ref": "conanfile",
        "id": "0",
        "recipe": "Consumer",
        "package_id": null,
        "prev": null,
        "remote": null,
        "binary_remote": null,
        "build_id": null,
        "binary": null,
        "invalid_build": false,
        "info_invalid": null,
        "name": null,
        "user": null,
        "channel": null,
        "url": null,
        "license": null,
        "author": null,
        "description": null,
        "homepage": null,
        "build_policy": null,
        "upload_policy": null,
        "revision_mode": "hash",
        "provides": null,
        "deprecated": null,
        "win_bash": null,
        "win_bash_run": null,
        "default_options": null,
        "options_description": null,
        "version": null,
        "topics": null,
        "package_type": "unknown",
        "settings": {
          "os": "Macos",
          "arch": "armv8",
          "compiler": "apple-clang",
          "compiler.cppstd": "gnu17",
          "compiler.libcxx": "libc++",
          "compiler.version": "14",
          "build_type": "Release"
        },
        "options": {},
        "options_definitions": {},
        "generators": [
          "CMakeDeps",
          "CMakeToolchain"
        ],
        "system_requires": {},
        "recipe_folder": null,
        "source_folder": null,
        "build_folder": null,
        "generators_folder": null,
        "package_folder": null,
        "cpp_info": {
          "root": {
            "includedirs": [
              "include"
            ],
            "srcdirs": null,
            "libdirs": [
              "lib"
            ],
            "resdirs": null,
            "bindirs": [
              "bin"
            ],
            "builddirs": null,
            "frameworkdirs": null,
            "system_libs": null,
            "frameworks": null,
            "libs": null,
            "defines": null,
            "cflags": null,
            "cxxflags": null,
            "sharedlinkflags": null,
            "exelinkflags": null,
            "objects": null,
            "sysroot": null,
            "requires": null,
            "properties": null
          }
        },
        "label": "conanfile.txt",
        "dependencies": {
          "1": {
            "ref": "zlib/1.2.11",
            "run": "False",
            "libs": "True",
            "skip": "False",
            "test": "False",
            "force": "False",
            "direct": "True",
            "build": "False",
            "transitive_headers": "None",
            "transitive_libs": "None",
            "headers": "True",
            "package_id_mode": "None",
            "visible": "True"
          }
        },
        "context": "host",
        "test": false
      },
      "1": {
        "ref": "zlib/1.2.11#ffa77daf83a57094149707928bdce823",
        "id": "1",
        "recipe": "Cache",
        "package_id": "76f7d863f21b130b4e6527af3b1d430f7f8edbea",
        "prev": null,
        "remote": null,
        "binary_remote": null,
        "build_id": null,
        "binary": "Missing",
        "invalid_build": false,
        "info_invalid": null,
        "name": "zlib",
        "user": null,
        "channel": null,
        "url": "https://github.com/conan-io/conan-center-index",
        "license": "Zlib",
        "author": null,
        "description": "A Massively Spiffy Yet Delicately Unobtrusive Compression Library (Also Free, Not to Mention Unencumbered by Patents)",
        "homepage": "https://zlib.net",
        "build_policy": null,
        "upload_policy": null,
        "revision_mode": "hash",
        "provides": null,
        "deprecated": null,
        "win_bash": null,
        "win_bash_run": null,
        "default_options": {
          "shared": false,
          "fPIC": true
        },
        "options_description": null,
        "version": "1.2.11",
        "topics": [
          "zlib",
          "compression"
        ],
        "package_type": "static-library",
        "settings": {
          "os": "Macos",
          "arch": "armv8",
          "compiler": "apple-clang",
          "compiler.version": "14",
          "build_type": "Release"
        },
        "options": {
          "fPIC": "True",
          "shared": "False"
        },
        "options_definitions": {
          "shared": [
            "True",
            "False"
          ],
          "fPIC": [
            "True",
            "False"
          ]
        },
        "generators": [],
        "system_requires": {},
        "recipe_folder": "/Users/tk/.conan2/p/zlib774aa77541f8b/e",
        "source_folder": null,
        "build_folder": null,
        "generators_folder": null,
        "package_folder": null,
        "cpp_info": {
          "root": {
            "includedirs": [
              "include"
            ],
            "srcdirs": null,
            "libdirs": [
              "lib"
            ],
            "resdirs": null,
            "bindirs": [
              "bin"
            ],
            "builddirs": null,
            "frameworkdirs": null,
            "system_libs": null,
            "frameworks": null,
            "libs": null,
            "defines": null,
            "cflags": null,
            "cxxflags": null,
            "sharedlinkflags": null,
            "exelinkflags": null,
            "objects": null,
            "sysroot": null,
            "requires": null,
            "properties": null
          }
        },
        "label": "zlib/1.2.11",
        "dependencies": {},
        "context": "host",
        "test": false
      }
    },
    "root": {
      "0": "None"
    },
    "overrides": {},
    "resolved_ranges": {}
  }
}
		`,
		expected: []model.Package{
			{Name: "zlib", Version: "1.2.11", Type: model.PkgTypeConan},
		},
	},
}

/*
conan_graph_parse.go 单测方法
*/
func TestParseConanGraph(t *testing.T) {
	for _, item := range conanGraphTestData {
		r := strings.NewReader(item.content)
		pkgs, err := parseConanGraphJsonFile(r, "")
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v got %v", item.title, item.expected, pkgs)
		}
	}
}

func TestParseConanfile(t *testing.T) {
	for _, item := range conanfileTestdata {
		r := strings.NewReader(item.content)
		licenseMap := make(map[string]string)
		pkgs, err := parseConanfile(r, "", licenseMap)
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v got %v", item.title, item.expected, pkgs)
		}
	}
}

func TestParseConanlock(t *testing.T) {
	for _, item := range conanlockTestdata {
		r := strings.NewReader(item.content)
		pkgs, err := parseConanlock(r, "")
		if err != nil {
			t.Errorf("test error[%v]: %e", item.title, err)
		}

		if !slices.EqualFunc(pkgs, item.expected, func(p1 model.Package, p2 model.Package) bool {
			return model.PackageEqual(&p1, &p2)
		}) {
			t.Errorf("test failed[%v]: expected = %v got %v", item.title, item.expected, pkgs)
		}
	}
}

func TestParseConanFileLicense(t *testing.T) {
	licenseMap := make(map[string]string)
	_, err := exec.Command("conan", " -v").Output()
	if err != nil {
		t.Skipf("Execution environment is not installed")
		return
	}
	licenseMap["zlib/1.2.11"] = "Zlib"
	license, err := getConanPkgLicense("test_material/conan/conanfile.txt")
	assert.NoError(t, err)
	if !reflect.DeepEqual(license, licenseMap) {
		t.Errorf("test failed")
	}
}

func BenchmarkCppConanFileParser_Parse(b *testing.B) {
	b.ResetTimer()
	for _, item := range conanfileTestdata {
		item := item
		b.Run(item.title, func(b *testing.B) {
			r := strings.NewReader(item.content)
			licenseMap := make(map[string]string)
			_, _ = parseConanfile(r, "", licenseMap)
		})
	}
}

func BenchmarkCppConanLockParser_Parse(b *testing.B) {
	b.ResetTimer()
	for _, item := range conanlockTestdata {
		item := item
		b.Run(item.title, func(b *testing.B) {
			r := strings.NewReader(item.content)
			_, _ = parseConanlock(r, "")
		})
	}
}
