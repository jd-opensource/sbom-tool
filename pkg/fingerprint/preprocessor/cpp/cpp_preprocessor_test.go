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
		int age;`,
		`
		int age;`,
	},
	{
		"single line 2",
		`////age
		 int age;`,
		`
		 int age;`,
	},
	{
		"inline 1",
		`int age;//age`,
		`int age;`,
	},
	{
		"inline 2",
		`int age;/*it's your age*/`,
		`int age;`,
	},
	{
		"multiline 1",
		`/**
		  * age 
		  */
		 int age;`,
		`
		 int age;`,
	},
}

func TestRemoveCommonKeywordLines(t *testing.T) {
	testCppCode := `
#include <stdlib.h>

int main(void) {
    char buffer_in [256] = {"string"};
    char buffer_out [256] = {0};
    z_stream defstream;
    printf("string: %lu\n", strlen(buffer_in));
    return EXIT_SUCCESS;
}
`
	expected := `intmain(void){
charbuffer_in[256]={"string"};
charbuffer_out[256]={0};
z_streamdefstream;
printf("string:%lu\n",strlen(buffer_in));
returnEXIT_SUCCESS;
}`
	actual := removeCommonKeywordLines(testCppCode)

	assert.Equal(t, expected, actual)
}

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			actual := removeComments(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestCppPreprocessor_ProcessContent(t *testing.T) {
	testCppCode := `
	#include <stdlib.h>
	/*
	test
	*/
	int main(void) {
		char buffer_in [256] = {"string"}; // test
		char buffer_out [256] = {0}; /* test */
		z_stream defstream;
		printf("string: %lu\n", strlen(buffer_in));
		return EXIT_SUCCESS;
	}
	`
	expected := `intmain(void){
charbuffer_in[256]={"string"};
charbuffer_out[256]={0};
z_streamdefstream;
printf("string:%lu\n",strlen(buffer_in));
returnEXIT_SUCCESS;
}`
	processor := NewCppPreprocessor()
	actual := processor.ProcessContent(testCppCode)
	assert.Equal(t, expected, actual)
}

func BenchmarkCppPreprocessor_ProcessContent(b *testing.B) {
	testCppCode := `
	#include <stdlib.h>
	/*
	test
	*/
	int main(void) {
		char buffer_in [256] = {"string"}; // test
		char buffer_out [256] = {0}; /* test */
		z_stream defstream;
		printf("string: %lu\n", strlen(buffer_in));
		return EXIT_SUCCESS;
	}
	`
	processor := NewCppPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testCppCode)
	}
}
