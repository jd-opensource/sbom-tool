// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package collector

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func TestFileNameMatcher_Match(t *testing.T) {
	type Args struct {
		names []string
		file  string
	}
	tests := []struct {
		name string
		args Args
		want bool
	}{
		{
			name: "normal",
			args: Args{
				names: []string{"test1.go"},
				file:  "test1.go",
			},
			want: true,
		}, {
			name: "multi",
			args: Args{
				names: []string{"test1.go", "test2.go"},
				file:  "test2.go",
			},
			want: true,
		}, {
			name: "not-matched",
			args: Args{
				names: []string{"test1.go"},
				file:  "test2.go",
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			m := &FileNameMatcher{Names: test.args.names}
			matched := m.Match(NewFileMeta(test.args.file))
			assert.Equal(tt, test.want, matched)
		})
	}
}

func TestFilePatternMatcher_Match(t *testing.T) {
	type Args struct {
		patterns []string
		file     string
	}
	tests := []struct {
		name string
		args Args
		want bool
	}{
		{
			name: "normal",
			args: Args{
				patterns: []string{"test1.go"},
				file:     "test1.go",
			},
			want: true,
		}, {
			name: "multi",
			args: Args{
				patterns: []string{"test1.go", "test?.go"},
				file:     "test2.go",
			},
			want: true,
		}, {
			name: "wildcard-1",
			args: Args{
				patterns: []string{"test?.go"},
				file:     "test1.go",
			},
			want: true,
		}, {
			name: "wildcard-2",
			args: Args{
				patterns: []string{"t*.go"},
				file:     "test1.go",
			},
			want: true,
		}, {
			name: "path-1",
			args: Args{
				patterns: []string{"test?/t*.go"},
				file:     "test1/test2.go",
			},
			want: true,
		}, {
			name: "path-2",
			args: Args{
				patterns: []string{"*/test.go"},
				file:     "test2/test.go",
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			m := FilePatternMatcher{Patterns: test.args.patterns}
			matched := m.Match(NewFileMeta(test.args.file))
			assert.Equal(tt, test.want, matched)
		})
	}
}

func TestFileRegexpMatcher_Match(t *testing.T) {
	type Args struct {
		regexps []string
		file    string
	}
	tests := []struct {
		name string
		args Args
		want bool
	}{
		{
			name: "normal",
			args: Args{
				regexps: []string{"test1.go"},
				file:    "test1.go",
			},
			want: true,
		}, {
			name: "multi",
			args: Args{
				regexps: []string{"test1.go", "test2.go"},
				file:    "test2.go",
			},
			want: true,
		}, {
			name: "not-matched",
			args: Args{
				regexps: []string{"test1.go"},
				file:    "test2.go",
			},
			want: false,
		}, {
			name: "multi-path",
			args: Args{
				regexps: []string{".*/test.go"},
				file:    "test1/test2/test.go",
			},
			want: true,
		}, {
			name: "multi-path",
			args: Args{
				regexps: []string{"^.*/test.go$"},
				file:    "test1/test2/test.go",
			},
			want: true,
		}, {
			name: "pypi-dist-mata",
			args: Args{
				regexps: []string{"^.*dist-info/METADATA$"},
				file:    "test/app-1.0.0-dist-info/METADATA",
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			m := &FileRegexpMatcher{Regexps: util.SliceMap(test.args.regexps, regexp.MustCompile)}
			matched := m.Match(NewFileMeta(test.args.file))
			assert.Equal(tt, test.want, matched)
		})
	}
}
