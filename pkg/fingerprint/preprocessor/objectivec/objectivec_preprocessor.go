// Copyright 2023 Jingdong Technology Information Technology Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package objectivec

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/pattern_set"
)

var (
	remove_block_comment_re    *regexp.Regexp
	remove_out_line_comment_re *regexp.Regexp
	remove_in_line_comment_re  *regexp.Regexp
	prefixSet                  *pattern_set.PatternSet
)

type Preprocessor struct{}

func NewObjectivecPreprocessor() preprocessor.PreProcessor {
	return &Preprocessor{}
}

func (p *Preprocessor) Name() string {
	return "objectivec"
}

func (p *Preprocessor) SupportedFileTypes() []string {
	return []string{".m"}
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
	content = remove_block_comment_re.ReplaceAllString(content, "")
	content = remove_in_line_comment_re.ReplaceAllString(content, "")
	content = remove_out_line_comment_re.ReplaceAllString(content, "")
	return content
}

func removeCommonKeywordLines(content string) string {
	buf := bytes.NewBuffer([]byte(content))
	var sb strings.Builder
	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF && line == "" {
			break
		}

		if err != nil && err != io.EOF {
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if prefixSet.Match(trimmed) {
			continue
		}

		if trimmed == "{" || trimmed == "}" {
			continue
		}

		sb.WriteString(trimmed)
		sb.WriteByte('\n')

		if err == io.EOF {
			break
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func init() {
	remove_block_comment_re = regexp.MustCompile(`(/\*{1,2}[\s\S]*?\*/)`)
	remove_out_line_comment_re = regexp.MustCompile(`(?m)^\s*//.*$`)
	remove_in_line_comment_re = regexp.MustCompile(`(?m)//.*$`)

	prefixSet = pattern_set.NewPrefixPatternMatchSet(
		"@end",
		"@interface",
		"@property",
		"@implementation",
		"@protocol",
		"@synthesize",
		"@dynamic",
		"#import",
		"#include",
		"#error",
		"#pragma",
		"#endif",
		"#define",
		"const",
		"interface",
		"static",
		"auto",
		"else",
		"switch",
		"break",
		"register",
		"typedef",
		"extern",
		"unsigned",
		"signed",
		"continue",
		"goto",
		"while",
		"do",
		"_Packed",
	)
}
