// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package csharp

import (
	"bytes"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	RX_COMMENTS *regexp.Regexp
	prefixSet   *pattern_set.PatternSet
)

type CSharpPreprocessor struct {
}

func NewCSharpPreprocessor() preprocessor.PreProcessor {
	return &CSharpPreprocessor{}
}
func (g CSharpPreprocessor) Name() string {
	return "csharp"
}

func (g CSharpPreprocessor) ProcessContent(content string) string {
	processFns := []func(content string) string{
		removeComments,
		removeCommonKeywordLines,
	}
	var code = content
	for _, processFn := range processFns {
		code = processFn(code)
	}
	return code
}

func (g CSharpPreprocessor) SupportedFileTypes() []string {
	return []string{".cs"}
}

func removeComments(content string) string {
	return RX_COMMENTS.ReplaceAllString(content, "")
}

func removeCommonKeywordLines(content string) string {
	buf := bytes.NewBuffer([]byte(content))
	var sb strings.Builder
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if prefixSet.Match(trimmed) {
			continue
		}
		sb.WriteString(trimmed)
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

func init() {
	RX_COMMENTS = regexp.MustCompile(`(?:/\*(?:[^*]|(?:\*+[^*/]))*\*+/)|(?://.*)`)
	prefixSet = pattern_set.NewPrefixPatternMatchSet(
		"}",
		"{",
		"@",
		"} else {",
		"break",
		"using",
	)

}
