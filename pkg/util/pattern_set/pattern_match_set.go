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

import (
	mapset "github.com/deckarep/golang-set"
)

type PatternSet struct {
	m       map[int]mapset.Set
	sliceFn SliceFn
}

type SliceFn func(content string, k int) string

func prefixSlicer(content string, k int) string {
	if len(content) < k {
		return ""
	}
	return content[0:k]
}

func suffixSlicer(content string, k int) string {
	if len(content) < k {
		return ""
	}
	return content[len(content)-k:]
}

// NewSet returns a new PatternMatchSet with patterns.
func NewSet(sliceFn SliceFn, patterns ...string) *PatternSet {
	patternSet := &PatternSet{m: make(map[int]mapset.Set)}
	for _, p := range patterns {
		patternSet.Add(p)
	}
	patternSet.sliceFn = sliceFn
	return patternSet
}

// NewPrefixPatternMatchSet returns a new PatternMatchSet with prefixes.
func NewPrefixPatternMatchSet(prefixes ...string) *PatternSet {
	p := &PatternSet{make(map[int]mapset.Set), prefixSlicer}
	p.AddAll(prefixes...)
	return p
}

// NewSuffixPatternMatchSet returns a new PatternMatchSet with suffixes.
func NewSuffixPatternMatchSet(suffixes ...string) *PatternSet {
	p := &PatternSet{make(map[int]mapset.Set), suffixSlicer}
	p.AddAll(suffixes...)
	return p
}

// AddAll adds all patterns to the set.
func (p *PatternSet) AddAll(patterns ...string) {
	for _, v := range patterns {
		p.Add(v)
	}
}

// Add adds a pattern to the set.
func (p *PatternSet) Add(pattern string) {
	n := len(pattern)
	if n == 0 {
		return
	}
	set := p.m[n]
	if set == nil {
		p.m[n] = mapset.NewSet(pattern)
		return
	}
	set.Add(pattern)
}

// Match returns true if the content matches any pattern.
func (p *PatternSet) Match(content string) bool {
	return len(p.MatchedSlice(content)) > 0
}

// MatchedSlice returns the matched slice of the content.
func (p *PatternSet) MatchedSlice(content string) string {
	if len(p.m) == 0 {
		return ""
	}

	for k, v := range p.m {
		if len(content) >= k {
			slice := p.sliceFn(content, k)
			if v.Contains(slice) {
				return slice
			}
		}
	}
	return ""
}
