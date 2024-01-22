// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package java

import (
	"bytes"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	regComments *regexp.Regexp
	prefixSet   *pattern_set.PatternSet
)

type Preprocessor struct{}

func NewJavaPreprocessor() preprocessor.PreProcessor {
	return &Preprocessor{}
}

func (p *Preprocessor) Name() string {
	return "java"
}

func (p *Preprocessor) SupportedFileTypes() []string {
	return []string{".java"}
}

func (p *Preprocessor) ProcessContent(content string) string {
	processFns := []func(content string) string{
		removeComments,
		removeCommonKeywordLines,
	}
	code := content
	for _, processFn := range processFns {
		code = processFn(code)
	}
	return code
}

func removeComments(content string) string {
	return regComments.ReplaceAllString(content, "")
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

	prefixSet = pattern_set.NewPrefixPatternMatchSet(
		"}",
		"{",
		"@",
		"} else {",
		"break",
		"package",
		"import",
	)
}
