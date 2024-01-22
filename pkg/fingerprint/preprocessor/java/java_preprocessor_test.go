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
		`//age
		 private int age;`,
		`
		 private int age;`,
	},
	{
		"single line 2",
		`////age
		 private int age;`,
		`
		 private int age;`,
	},
	{
		"inline 1",
		`private int age;//age`,
		`private int age;`,
	},
	{
		"inline 2",
		`private int age;/*it's your age*/`,
		`private int age;`,
	},
	{
		"multiline 1",
		`/**
		  * age 
		  */
		 private int age;`,
		`
		 private int age;`,
	},
}

func TestRemoveComments(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			actual := removeComments(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestRemoveCommonKeywordLines(t *testing.T) {
	src := `import com.jd;
	package com.jd.sso;
	@Override
	public void print() {
	}`

	expected := `public void print() {`
	actual := removeCommonKeywordLines(src)

	assert.Equal(t, expected, actual)
}

func TestJavaPreprocessor_ProcessContent(t *testing.T) {
	src := `import com.example.demo;
	package com.example.test;
	public class Test {
		@Override
		private void print() {
			int a;
			String a = "xxx";
		}
		public main(String args[]) {
			System.out.println("hello");
		}
	}
`
	expected := `public class Test {
private void print() {
int a;
String a = "xxx";
public main(String args[]) {
System.out.println("hello");`
	processor := NewJavaPreprocessor()
	got := processor.ProcessContent(src)
	assert.Equal(t, expected, got)
}

func BenchmarkJavaPreprocessor_ProcessContent(b *testing.B) {
	src := `import com.example.demo;
	package com.example.test;
	public class Test {
		@Override
		private void print() {
			int a;
			String a = "xxx";
		}
		public main(String args[]) {
			System.out.println("hello");
		}
	}
`
	processor := NewJavaPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(src)
	}
}
