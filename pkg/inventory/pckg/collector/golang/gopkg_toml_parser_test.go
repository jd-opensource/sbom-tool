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
	"reflect"
	"testing"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
)

func TestParseGopkgTOML(t *testing.T) {
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
			args{path: "test_material/dep/Gopkg.toml"},
			[]model.Package{
				*newPackage("github.com/Masterminds/semver", "", "test_material/dep/Gopkg.toml"),
				*newPackage("github.com/Masterminds/vcs", "1.11.0", "test_material/dep/Gopkg.toml"),
				*newPackage("github.com/boltdb/bolt", "1.0.0", "test_material/dep/Gopkg.toml"),
				*newPackage("github.com/jmank88/nuts", "0.3.0", "test_material/dep/Gopkg.toml"),
				*newPackage("github.com/pelletier/go-toml", "1.2.0", "test_material/dep/Gopkg.toml"),
				*newPackage("github.com/pkg/errors", "0.8.0", "test_material/dep/Gopkg.toml"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGopkgToml(tt.args.path)
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

func TestParseGopkgLock(t *testing.T) {
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
			args{path: "test_material/dep/Gopkg.lock"},
			[]model.Package{
				*newPackage("github.com/Masterminds/semver", "24642bd0573145a5ee04f9be773641695289be46", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/Masterminds/vcs", "v1.11.1", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/armon/go-radix", "4239b77079c7b5d1243b7b4736304ce8ddb6f0f2", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/boltdb/bolt", "v1.3.1", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/golang/protobuf", "v1.0.0", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/google/go-cmp", "v0.2.0", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/jmank88/nuts", "v0.3.0", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/nightlyone/lockfile", "e83dc5e7bba095e8d32fb2124714bf41f2a30cb5", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/pelletier/go-toml", "v1.2.0", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/pkg/errors", "v0.8.0", "test_material/dep/Gopkg.lock"),
				*newPackage("github.com/sdboyer/constext", "836a144573533ea4da4e6929c235fd348aed1c80", "test_material/dep/Gopkg.lock"),
				*newPackage("golang.org/x/net", "66aacef3dd8a676686c7ae3716979581e8b03c47", "test_material/dep/Gopkg.lock"),
				*newPackage("golang.org/x/sync", "f52d1811a62927559de87708c8913c1650ce4f26", "test_material/dep/Gopkg.lock"),
				*newPackage("golang.org/x/sys", "bb24a47a89eac6c1227fbcb2ae37a8b9ed323366", "test_material/dep/Gopkg.lock"),
				*newPackage("gopkg.in/yaml.v2", "d670f9405373e636a5a2765eea47fac0c9bc91a4", "test_material/dep/Gopkg.lock"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGopkgLock(tt.args.path)
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

func BenchmarkGopkgTOMLParser(b *testing.B) {
	g := GopkgTOMLParser{}
	for i := 0; i < b.N; i++ {
		_, _ = g.Parse("test_material/dep/Gopkg.toml")
	}
}
