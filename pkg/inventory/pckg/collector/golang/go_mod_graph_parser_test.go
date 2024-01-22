// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package golang

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/JD-opensource/sbom-tool/pkg/model"
)

func TestGoModGraphParser_Parse(t *testing.T) {

	wantJson := `[
    {
        "name": "github.com/davecgh/go-spew",
        "version": "v1.1.0",
        "type": "golang",
        "purl": "pkg:golang/github.com/davecgh/go-spew@v1.1.0",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/davecgh/go-spew",
        "version": "v1.1.1",
        "type": "golang",
        "purl": "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/google/go-cmp",
        "version": "v0.5.8",
        "type": "golang",
        "purl": "pkg:golang/github.com/google/go-cmp@v0.5.8",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/incu6us/goimports-reviser/v3",
        "version": "",
        "type": "golang",
        "purl": "pkg:golang/github.com/incu6us/goimports-reviser/v3",
        "dependencies": [
            "pkg:golang/github.com/kr/pretty@v0.1.0",
            "pkg:golang/github.com/pmezard/go-difflib@v1.0.0",
            "pkg:golang/github.com/stretchr/testify@v1.6.1",
            "pkg:golang/golang.org/x/exp@v0.0.0-20220722155223-a9213eeb770e",
            "pkg:golang/golang.org/x/mod@v0.6.0-dev.0.20220106191415-9b9b3d81d5e3",
            "pkg:golang/golang.org/x/sys@v0.1.0",
            "pkg:golang/golang.org/x/tools@v0.1.10",
            "pkg:golang/golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
            "pkg:golang/gopkg.in/check.v1@v1.0.0-20190902080502-41f04d3bba15",
            "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/kr/pretty",
        "version": "v0.1.0",
        "type": "golang",
        "purl": "pkg:golang/github.com/kr/pretty@v0.1.0",
        "dependencies": [
            "pkg:golang/github.com/kr/text@v0.1.0"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/kr/pty",
        "version": "v1.1.1",
        "type": "golang",
        "purl": "pkg:golang/github.com/kr/pty@v1.1.1",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/kr/text",
        "version": "v0.1.0",
        "type": "golang",
        "purl": "pkg:golang/github.com/kr/text@v0.1.0",
        "dependencies": [
            "pkg:golang/github.com/kr/pty@v1.1.1"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/pmezard/go-difflib",
        "version": "v1.0.0",
        "type": "golang",
        "purl": "pkg:golang/github.com/pmezard/go-difflib@v1.0.0",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/stretchr/objx",
        "version": "v0.1.0",
        "type": "golang",
        "purl": "pkg:golang/github.com/stretchr/objx@v0.1.0",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/stretchr/testify",
        "version": "v1.6.1",
        "type": "golang",
        "purl": "pkg:golang/github.com/stretchr/testify@v1.6.1",
        "dependencies": [
            "pkg:golang/github.com/davecgh/go-spew@v1.1.0",
            "pkg:golang/github.com/pmezard/go-difflib@v1.0.0",
            "pkg:golang/github.com/stretchr/objx@v0.1.0",
            "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "github.com/yuin/goldmark",
        "version": "v1.4.1",
        "type": "golang",
        "purl": "pkg:golang/github.com/yuin/goldmark@v1.4.1",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/crypto",
        "version": "v0.0.0-20210921155107-089bfa567519",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/exp",
        "version": "v0.0.0-20220722155223-a9213eeb770e",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/exp@v0.0.0-20220722155223-a9213eeb770e",
        "dependencies": [
            "pkg:golang/github.com/google/go-cmp@v0.5.8",
            "pkg:golang/golang.org/x/mod@v0.6.0-dev.0.20220106191415-9b9b3d81d5e3",
            "pkg:golang/golang.org/x/sys@v0.0.0-20211019181941-9d821ace8654",
            "pkg:golang/golang.org/x/tools@v0.1.10",
            "pkg:golang/golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/mod",
        "version": "v0.6.0-dev.0.20220106191415-9b9b3d81d5e3",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/mod@v0.6.0-dev.0.20220106191415-9b9b3d81d5e3",
        "dependencies": [
            "pkg:golang/golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519",
            "pkg:golang/golang.org/x/tools@v0.0.0-20191119224855-298f0cb1881e",
            "pkg:golang/golang.org/x/xerrors@v0.0.0-20191011141410-1b5146add898"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/net",
        "version": "v0.0.0-20211015210444-4f30a5c0130f",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/net@v0.0.0-20211015210444-4f30a5c0130f",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/sync",
        "version": "v0.0.0-20210220032951-036812b2e83c",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/sync@v0.0.0-20210220032951-036812b2e83c",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/sys",
        "version": "v0.0.0-20211019181941-9d821ace8654",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/sys@v0.0.0-20211019181941-9d821ace8654",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/sys",
        "version": "v0.1.0",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/sys@v0.1.0",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/text",
        "version": "v0.3.7",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/text@v0.3.7",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/tools",
        "version": "v0.0.0-20191119224855-298f0cb1881e",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/tools@v0.0.0-20191119224855-298f0cb1881e",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/tools",
        "version": "v0.1.10",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/tools@v0.1.10",
        "dependencies": [
            "pkg:golang/github.com/yuin/goldmark@v1.4.1",
            "pkg:golang/golang.org/x/mod@v0.6.0-dev.0.20220106191415-9b9b3d81d5e3",
            "pkg:golang/golang.org/x/net@v0.0.0-20211015210444-4f30a5c0130f",
            "pkg:golang/golang.org/x/sync@v0.0.0-20210220032951-036812b2e83c",
            "pkg:golang/golang.org/x/sys@v0.0.0-20211019181941-9d821ace8654",
            "pkg:golang/golang.org/x/text@v0.3.7",
            "pkg:golang/golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/xerrors",
        "version": "v0.0.0-20191011141410-1b5146add898",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/xerrors@v0.0.0-20191011141410-1b5146add898",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "golang.org/x/xerrors",
        "version": "v0.0.0-20200804184101-5ec99f83aff1",
        "type": "golang",
        "purl": "pkg:golang/golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "gopkg.in/check.v1",
        "version": "v0.0.0-20161208181325-20d25e280405",
        "type": "golang",
        "purl": "pkg:golang/gopkg.in/check.v1@v0.0.0-20161208181325-20d25e280405",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "gopkg.in/check.v1",
        "version": "v1.0.0-20190902080502-41f04d3bba15",
        "type": "golang",
        "purl": "pkg:golang/gopkg.in/check.v1@v1.0.0-20190902080502-41f04d3bba15",
        "dependencies": null,
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    },
    {
        "name": "gopkg.in/yaml.v3",
        "version": "v3.0.0-20200313102051-9f266ea9e77c",
        "type": "golang",
        "purl": "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
        "dependencies": [
            "pkg:golang/gopkg.in/check.v1@v0.0.0-20161208181325-20d25e280405"
        ],
        "sourceLocation": "test_material/gomod/go-mod-graph.txt"
    }
]`
	wantPkgs := make([]model.Package, 0)
	err := json.Unmarshal([]byte(wantJson), &wantPkgs)
	assert.NoError(t, err)
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []model.Package
		wantErr bool
	}{
		{
			"case-1",
			args{path: "test_material/gomod/go-mod-graph.txt"},
			wantPkgs,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GoModGraphParser{}
			got, err := g.Parse(tt.args.path)

			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Collect() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkGoModGraphParser(b *testing.B) {
	g := GoModGraphParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/gomod/go-mod-graph.txt")
	}
}
