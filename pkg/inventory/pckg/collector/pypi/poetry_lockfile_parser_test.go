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

func TestParsePoetryLockFile(t *testing.T) {
	expected := `[
    {
        "name": "atomicwrites",
        "version": "1.4.1",
        "type": "pypi",
        "purl": "pkg:pypi/atomicwrites@1.4.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "attrs",
        "version": "22.2.0",
        "type": "pypi",
        "purl": "pkg:pypi/attrs@22.2.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
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
        "version": "2.0.12",
        "type": "pypi",
        "purl": "pkg:pypi/charset-normalizer@2.0.12",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "click",
        "version": "8.0.4",
        "type": "pypi",
        "purl": "pkg:pypi/click@8.0.4",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/colorama@0.4.5",
            "pkg:pypi/importlib-metadata@4.8.3"
        ]
    },
    {
        "name": "colorama",
        "version": "0.4.5",
        "type": "pypi",
        "purl": "pkg:pypi/colorama@0.4.5",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "dataclasses",
        "version": "0.8",
        "type": "pypi",
        "purl": "pkg:pypi/dataclasses@0.8",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "flask",
        "version": "2.0.3",
        "type": "pypi",
        "purl": "pkg:pypi/flask@2.0.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/Jinja2",
            "pkg:pypi/Werkzeug",
            "pkg:pypi/click@8.0.4",
            "pkg:pypi/itsdangerous@2.0.1"
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
        "version": "4.8.3",
        "type": "pypi",
        "purl": "pkg:pypi/importlib-metadata@4.8.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/typing-extensions@4.1.1",
            "pkg:pypi/zipp@3.6.0"
        ]
    },
    {
        "name": "itsdangerous",
        "version": "2.0.1",
        "type": "pypi",
        "purl": "pkg:pypi/itsdangerous@2.0.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "jinja2",
        "version": "3.0.3",
        "type": "pypi",
        "purl": "pkg:pypi/jinja2@3.0.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/MarkupSafe"
        ]
    },
    {
        "name": "markupsafe",
        "version": "2.0.1",
        "type": "pypi",
        "purl": "pkg:pypi/markupsafe@2.0.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "more-itertools",
        "version": "8.14.0",
        "type": "pypi",
        "purl": "pkg:pypi/more-itertools@8.14.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "packaging",
        "version": "21.3",
        "type": "pypi",
        "purl": "pkg:pypi/packaging@21.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/pyparsing@3.0.7"
        ]
    },
    {
        "name": "pluggy",
        "version": "0.13.1",
        "type": "pypi",
        "purl": "pkg:pypi/pluggy@0.13.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/importlib-metadata@4.8.3"
        ]
    },
    {
        "name": "py",
        "version": "1.11.0",
        "type": "pypi",
        "purl": "pkg:pypi/py@1.11.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "pyparsing",
        "version": "3.0.7",
        "type": "pypi",
        "purl": "pkg:pypi/pyparsing@3.0.7",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "pytest",
        "version": "5.4.3",
        "type": "pypi",
        "purl": "pkg:pypi/pytest@5.4.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/atomicwrites@1.4.1",
            "pkg:pypi/attrs@22.2.0",
            "pkg:pypi/colorama@0.4.5",
            "pkg:pypi/importlib-metadata@4.8.3",
            "pkg:pypi/more-itertools@8.14.0",
            "pkg:pypi/packaging@21.3",
            "pkg:pypi/pluggy@0.13.1",
            "pkg:pypi/py@1.11.0",
            "pkg:pypi/wcwidth@0.2.6"
        ]
    },
    {
        "name": "requests",
        "version": "2.27.1",
        "type": "pypi",
        "purl": "pkg:pypi/requests@2.27.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/certifi@2023.7.22",
            "pkg:pypi/charset-normalizer@2.0.12",
            "pkg:pypi/idna@3.4",
            "pkg:pypi/urllib3@1.26.16"
        ]
    },
    {
        "name": "typing-extensions",
        "version": "4.1.1",
        "type": "pypi",
        "purl": "pkg:pypi/typing-extensions@4.1.1",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "urllib3",
        "version": "1.26.16",
        "type": "pypi",
        "purl": "pkg:pypi/urllib3@1.26.16",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "wcwidth",
        "version": "0.2.6",
        "type": "pypi",
        "purl": "pkg:pypi/wcwidth@0.2.6",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    },
    {
        "name": "werkzeug",
        "version": "2.0.3",
        "type": "pypi",
        "purl": "pkg:pypi/werkzeug@2.0.3",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies":
        [
            "pkg:pypi/dataclasses@0.8"
        ]
    },
    {
        "name": "zipp",
        "version": "3.6.0",
        "type": "pypi",
        "purl": "pkg:pypi/zipp@3.6.0",
        "supplier": "",
        "filesAnalyzed": false,
        "verificationCode": "",
        "licenseConcluded": null,
        "licenseDeclared": null,
        "dependencies": null
    }
]
`
	path := "test_material/poetrylock/poetry.lock"
	parser := NewPoetryLockParser()
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

func BenchmarkPoetrylockFileParser(b *testing.B) {
	parse := NewPoetryLockParser()
	for i := 0; i < b.N; i++ {
		_, _ = parse.Parse("test_material/poetrylock/poetry.lock")
	}
}
