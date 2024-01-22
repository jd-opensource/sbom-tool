// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pypi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestParsePipenvGraphFile(t *testing.T) {
	expected := `[
    {
        "name": "Flask",
        "version": "2.2.5",
        "type": "pypi",
        "purl": "pkg:pypi/Flask@2.2.5",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/Jinja2@3.1.2",
            "pkg:pypi/Werkzeug@2.2.3",
            "pkg:pypi/click@8.1.7",
            "pkg:pypi/importlib-metadata@6.7.0",
            "pkg:pypi/itsdangerous@2.1.2"
        ]
    },
    {
        "name": "Jinja2",
        "version": "3.1.2",
        "type": "pypi",
        "purl": "pkg:pypi/Jinja2@3.1.2",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/MarkupSafe@2.1.3"
        ]
    },
    {
        "name": "MarkupSafe",
        "version": "2.1.3",
        "type": "pypi",
        "purl": "pkg:pypi/MarkupSafe@2.1.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded":
        [],
        "licenseDeclared":
        [],
        "dependencies":
        []
    },
    {
        "name": "Werkzeug",
        "version": "2.2.3",
        "type": "pypi",
        "purl": "pkg:pypi/Werkzeug@2.2.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/MarkupSafe@2.1.3"
        ]
    },
    {
        "name": "certifi",
        "version": "2023.7.22",
        "type": "pypi",
        "purl": "pkg:pypi/certifi@2023.7.22",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "charset-normalizer",
        "version": "3.2.0",
        "type": "pypi",
        "purl": "pkg:pypi/charset-normalizer@3.2.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "click",
        "version": "8.1.7",
        "type": "pypi",
        "purl": "pkg:pypi/click@8.1.7",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/importlib-metadata@6.7.0"
        ]
    },
    {
        "name": "idna",
        "version": "3.4",
        "type": "pypi",
        "purl": "pkg:pypi/idna@3.4",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "importlib-metadata",
        "version": "6.7.0",
        "type": "pypi",
        "purl": "pkg:pypi/importlib-metadata@6.7.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded":
        [],
        "licenseDeclared":
        [],
        "dependencies":
        [
            "pkg:pypi/typing-extensions@4.7.1",
            "pkg:pypi/zipp@3.15.0"
        ]
    },
    {
        "name": "itsdangerous",
        "version": "2.1.2",
        "type": "pypi",
        "purl": "pkg:pypi/itsdangerous@2.1.2",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "requests",
        "version": "2.31.0",
        "type": "pypi",
        "purl": "pkg:pypi/requests@2.31.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/certifi@2023.7.22",
            "pkg:pypi/charset-normalizer@3.2.0",
            "pkg:pypi/idna@3.4",
            "pkg:pypi/urllib3@2.0.4"
        ]
    },
    {
        "name": "typing-extensions",
        "version": "4.7.1",
        "type": "pypi",
        "purl": "pkg:pypi/typing-extensions@4.7.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded":
        [],
        "licenseDeclared":
        [],
        "dependencies":
        []
    },
    {
        "name": "urllib3",
        "version": "2.0.4",
        "type": "pypi",
        "purl": "pkg:pypi/urllib3@2.0.4",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "zipp",
        "version": "3.15.0",
        "type": "pypi",
        "purl": "pkg:pypi/zipp@3.15.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded":
        [],
        "licenseDeclared":
        [],
        "dependencies":
        []
    }
]`
	path := "test_material/pipenv-graph/pipenv-graph.txt"
	parser := NewPipenvGraphParser()
	pkgs, err := parser.Parse(path)
	if err != nil {
		t.Errorf("pkgs collect : +%v", err)
	}

	expectedPkgs := make([]model.Package, 0)

	err = json.Unmarshal([]byte(expected), &expectedPkgs)
	assert.NoError(t, err)

	if !slices.EqualFunc(expectedPkgs, pkgs, func(s1 model.Package, s2 model.Package) bool {
		return model.PackageEqual(&s1, &s2)
	}) {
		t.Errorf("Parse() got = %v, want %v", pkgs, expectedPkgs)
	}

}
