// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package php

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

func NewPhpPreprocessor() preprocessor.PreProcessor {
	return &Preprocessor{}
}

func (p *Preprocessor) Name() string {
	return "php"
}

func (p *Preprocessor) SupportedFileTypes() []string {
	return []string{".php"}
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
	content = remove_out_line_comment_re.ReplaceAllString(content, "")
	content = remove_in_line_comment_re.ReplaceAllString(content, "")
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
		"}",
		"{",
		"elseif",
		"echo",
		"else",
		"empty",
		"endfor",
		"enddeclare",
		"endif",
		"endforeach",
		"endswitch",
		"exit",
		"endwhile",
		"eval",
		"extends",
		"final",
		"foreach",
		"for",
		"if",
		"goto",
		"global",
		"interface",
		"insteadof",
		"instanceof",
		"implements",
		"isset",
		"list",
		"new",
		"or",
		"xor",
		"unset",
		"var",
		"while",
		"self",
		"this",
		"print",
		"switch",
		"throw",
		"trait",
		"try",
		"abstract",
		"and",
		"array",
		"as",
		"break",
		"callable",
		"case",
		"catch",
		"class",
		"clone",
		"continue",
		"declare",
		"default",
		"return",
		"do",
		"die",
		"include",
		"require",
		"include_once",
		"require_once",
		"use",
		"namespace",
		"static",
		"const",
		"private",
		"protected",
		"public",
		"__halt_compiler",
	)
}
