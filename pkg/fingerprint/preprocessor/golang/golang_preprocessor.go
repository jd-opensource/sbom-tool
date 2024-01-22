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
	"bytes"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	regComments                 *regexp.Regexp
	regImportWithoutParentheses *regexp.Regexp
	regImportWithParentheses    *regexp.Regexp
	prefixSet                   *pattern_set.PatternSet
)

type Preprocessor struct{}

func NewGolangPreprocessor() preprocessor.PreProcessor {
	return &Preprocessor{}
}

func (g Preprocessor) Name() string {
	return "golang"
}

func (g Preprocessor) ProcessContent(content string) string {
	processFns := []func(content string) string{
		removeComments,
		removeImports,
		removeCommonKeywordLines,
	}
	code := content
	for _, processFn := range processFns {
		code = processFn(code)
	}
	return code
}

func (g Preprocessor) SupportedFileTypes() []string {
	return []string{".go"}
}

func removeComments(content string) string {
	return regComments.ReplaceAllString(content, "")
}

func removeImports(content string) string {
	text := regImportWithoutParentheses.ReplaceAllString(content, "")
	text = regImportWithParentheses.ReplaceAllString(text, "")
	return text
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
	regComments = regexp.MustCompile(`(?:/\*(?:[^*]|(?:\*+[^*/]))*\*+/)|(?://.*)`)
	regImportWithoutParentheses = regexp.MustCompile(`import\s+[\"\']\S+`)
	regImportWithParentheses = regexp.MustCompile(`import\s*\([\s\S]*?\)`)
	prefixSet = pattern_set.NewPrefixPatternMatchSet(
		"}",
		"{",
		"@",
		"} else {",
		"break",
		"package",
	)

}
