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
	"testing"

	"github.com/stretchr/testify/assert"
)

var comments = []struct {
	name     string
	code     string
	expected string
}{
	{
		"single line 1",
		`// 这是一个单行注释
	         $name1 = "John";`,
		`$name1 = "John";`,
	},
	{
		"single line 2",
		`//这是一个单行注释
              $name2 = "John";`,
		`$name2 = "John";`,
	},
	{
		"inline 1",
		`$name3 = "John"; // 设置变量 $name`,
		`$name3 = "John";`,
	},
	{
		"multiline 1",
		`/*
			这是一个多行注释
			可以跨越多行
			*/
            $name4 = "John";`,
		`$name4 = "John";`,
	},
	{
		"multiline 2",
		`/**
			 * 这是一个函数的文档注释
			 *
			 * @param string $name 用户名
			 * @return string 欢迎消息
			 */
             $name5 = "John";`,
		`$name5 = "John";`,
	},
}

var testPhpCode = `<?php
			
			// 这是一个单行注释
            //这是一个单行注释
			$name = "John"; // 设置变量 $name
			
			/*
			这是一个多行注释
			可以跨越多行
			*/
			
			/**
			 * 这是一个函数的文档注释
			 *
			 * @param string $name 用户名
			 * @return string 欢迎消息
			 */
			function greet($name) {
				return "欢迎，default" . $name . "!";
			}
			// 调用 greet() 函数并输出结果
			echo greet($name);
			
			?>
			`

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			processor := NewPhpPreprocessor()
			actual := processor.ProcessContent(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestPhpPreprocessor_ProcessContent(t *testing.T) {
	expected_code := `<?php
$name = "John";
function greet($name) {
?>`
	processor := NewPhpPreprocessor()
	actual := processor.ProcessContent(testPhpCode)
	assert.Equal(t, expected_code, actual)
}

func BenchmarkPhpPreprocessor_ProcessContent(b *testing.B) {
	processor := NewPhpPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testPhpCode)
	}
}
