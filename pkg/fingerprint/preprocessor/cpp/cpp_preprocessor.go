// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package cpp

import (
	"bytes"
	"regexp"
	"strings"

	"gitee.com/JD-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	headers           = []string{"#include", "#import", "#ifndef", "#define", "#endif", "#ifdef", "#else"}
	regRmCommentBlock *regexp.Regexp
	regRmCommentLine  *regexp.Regexp
	regRmBlank        *regexp.Regexp
)

var headerPrefixSet *pattern_set.PatternSet

func init() {
	regRmCommentBlock = regexp.MustCompile(`/\*{1,2}[\s\S]*?\*/`)
	regRmCommentLine = regexp.MustCompile(`(//[^\n]*)`)
	regRmBlank = regexp.MustCompile(`[ \t\r\f]+`)

	headerPrefixSet = pattern_set.NewPrefixPatternMatchSet(headers...)

}

type Preprocessor struct{}

func NewCppPreprocessor() preprocessor.PreProcessor {
	return &Preprocessor{}
}

func (p *Preprocessor) Name() string {
	return "cpp"
}

func (p *Preprocessor) SupportedFileTypes() []string {
	return []string{".cpp", ".hpp", ".c", ".h"}
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
	content = regRmCommentBlock.ReplaceAllString(content, "")
	content = regRmCommentLine.ReplaceAllString(content, "")
	return content
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

		if headerPrefixSet.Match(trimmed) {
			continue
		}

		trimmed = removeWhitespaces(trimmed)

		sb.WriteString(trimmed)
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

func removeWhitespaces(content string) string {
	return regRmBlank.ReplaceAllString(content, "")
}
