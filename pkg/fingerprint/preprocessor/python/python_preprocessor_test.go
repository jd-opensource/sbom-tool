// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package python

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
		`#counter
	         counter = 100`,
		`counter = 100`,
	},
	{
		"single line 2",
		`# -*- coding: UTF-8 -*-`,
		``,
	},
	{
		"inline 1",
		`name = "John" # 字符串`,
		`name = "John"`,
	},
	{
		"multiline 1",
		`'''
	      comment
	    '''
		 c = 100`,
		`c = 100`,
	},
	{
		"multiline 2",
		`"""
	       comment
	     """
		 b = 100`,
		`b = 100`,
	},
}

var testPythonCode = `import boto3
		
		# 创建S3客户端
		s3 = boto3.client('s3')

		file_nameas = 'example.txt' # 指定要上传的文件和存储桶名称
		"""
        bucket_name 
        """
		bucket_name = 'my-bucket'
		
		'''
        上传文件
        '''
		s3.upload_file(file_name, bucket_name, file_name)

        '''test1'''
        """test2"""
		 """
		 test3"""
        '''
         test4'''
		print("文件上传成功！")
	`

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			processor := NewPythonPreprocessor()
			actual := processor.ProcessContent(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestPythonPreprocessor_ProcessContent(t *testing.T) {
	expected_code := `s3 = boto3.client('s3')
file_nameas = 'example.txt'
bucket_name = 'my-bucket'
s3.upload_file(file_name, bucket_name, file_name)`
	processor := NewPythonPreprocessor()
	actual := processor.ProcessContent(testPythonCode)
	assert.Equal(t, expected_code, actual)
}

func BenchmarkCppPreprocessor_ProcessContent(b *testing.B) {
	processor := NewPythonPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testPythonCode)
	}
}
