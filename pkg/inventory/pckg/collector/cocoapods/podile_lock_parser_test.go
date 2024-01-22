// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cocoapods

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestPodfileLockParser_Parse(t *testing.T) {
	expectJson := `[
    {
        "name": "AFNetworking/NSURLSession",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking/NSURLSession@4.0.1",
        "dependencies": [
            "pkg:cocoapods/AFNetworking/Reachability@4.0.1",
            "pkg:cocoapods/AFNetworking/Security@4.0.1",
            "pkg:cocoapods/AFNetworking/Serialization@4.0.1"
        ],
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "AFNetworking/Reachability",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking/Reachability@4.0.1",
        "dependencies": null,
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "AFNetworking/Security",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking/Security@4.0.1",
        "dependencies": null,
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "AFNetworking/Serialization",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking/Serialization@4.0.1",
        "dependencies": null,
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "AFNetworking/UIKit",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking/UIKit@4.0.1",
        "dependencies": [
            "pkg:cocoapods/AFNetworking/NSURLSession@4.0.1"
        ],
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "AFNetworking",
        "version": "4.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/AFNetworking@4.0.1",
        "dependencies": [
            "pkg:cocoapods/AFNetworking/NSURLSession@4.0.1",
            "pkg:cocoapods/AFNetworking/Reachability@4.0.1",
            "pkg:cocoapods/AFNetworking/Security@4.0.1",
            "pkg:cocoapods/AFNetworking/Serialization@4.0.1",
            "pkg:cocoapods/AFNetworking/UIKit@4.0.1"
        ],
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "FLKAutoLayout",
        "version": "0.2.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/FLKAutoLayout@0.2.1",
        "dependencies": null,
        "sourceLocation": "./test_material/Podfile.lock"
    },
    {
        "name": "ORStackView",
        "version": "3.0.1",
        "type": "cocoapods",
        "purl": "pkg:cocoapods/ORStackView@3.0.1",
        "dependencies": [
            "pkg:cocoapods/FLKAutoLayout@0.2.1"
        ],
        "sourceLocation": "./test_material/Podfile.lock"
    }
]`
	expectPkgs := make([]model.Package, 0)
	err := json.Unmarshal([]byte(expectJson), &expectPkgs)
	assert.NoError(t, err)

	parser := NewPodfileLockParser()
	pkgs, err := parser.Parse("./test_material/Podfile.lock")
	if err != nil {
		return
	}

	assert.Equal(t, expectPkgs, pkgs)
}
