// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pattern_set

import "testing"

func TestAdd(t *testing.T) {
	p := NewPrefixPatternMatchSet()
	p.Add("a")
	p.Add("bb")
	p.Add("cc")
	m := p.m
	oneSet := m[1]
	if oneSet == nil || !oneSet.Contains("a") {
		t.Error("expected [a] got nil")
	}

	twoSet := m[2]
	if twoSet == nil || !twoSet.Contains("bb") || !twoSet.Contains("cc") {
		t.Error("expected [bb, cc] got nil")
	}
}

var prefixes = []struct {
	ps                   []string
	line                 string
	expected             bool
	expectedMatchedSlice string
}{
	{
		nil,
		"",
		false,
		"",
	},
	{
		nil,
		"import com.jd.sso;",
		false,
		"",
	},
	{
		[]string{""},
		"import com.jd.sso;",
		false,
		"",
	},
	{
		[]string{"import"},
		"import com.jd.sso;",
		true,
		"import",
	},
	{
		[]string{"import", "package", "@", "}"},
		"@Controller",
		true,
		"@",
	},
	{
		[]string{"import", "package", "@", "}"},
		"}",
		true,
		"}",
	},
}

func TestMatch(t *testing.T) {
	for i, data := range prefixes {
		p := NewPrefixPatternMatchSet(data.ps...)

		actual := p.Match(data.line)
		if actual != data.expected {
			t.Errorf("test data id[%d], expected %v got %v", i, data.expected, actual)
		}
	}
}

func TestMatchedSlice(t *testing.T) {
	for i, data := range prefixes {
		p := NewPrefixPatternMatchSet(data.ps...)

		actual := p.MatchedSlice(data.line)
		if actual != data.expectedMatchedSlice {
			t.Errorf("test data id[%d], expected %v got %v", i, data.expectedMatchedSlice, actual)
		}
	}
}

var suffixes = []struct {
	ps                   []string
	line                 string
	expected             bool
	expectedMatchedSlice string
}{
	{
		nil,
		"",
		false,
		"",
	},
	{
		[]string{},
		"/a/b/c/d.java",
		false,
		"",
	},
	{
		[]string{".go", ".java", ".c", ".js"},
		"/a/b/c/d.java",
		true,
		".java",
	},
	{
		[]string{".go", ".java", ".c", ".js"},
		"/a/b/c/d.clj",
		false,
		"",
	},
}

func TestSuffixMatch(t *testing.T) {
	for i, data := range suffixes {
		p := NewSuffixPatternMatchSet(data.ps...)

		actual := p.Match(data.line)
		if actual != data.expected {
			t.Errorf("test data id[%d], expected %v got %v", i, data.expected, actual)
		}
	}
}

func TestSuffixMatchedSlice(t *testing.T) {
	for i, data := range suffixes {
		p := NewSuffixPatternMatchSet(data.ps...)

		actual := p.MatchedSlice(data.line)
		if actual != data.expectedMatchedSlice {
			t.Errorf("test data id[%d], expected %v got %v", i, data.expectedMatchedSlice, actual)
		}
	}
}
