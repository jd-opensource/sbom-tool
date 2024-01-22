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

func TestCSharpPreprocessor_ProcessContent(t *testing.T) {
	src := `using System;
namespace consoleTest
{
	public class BubbleSort : ISort
    {
		public BubbleSort()
		{
		}

        //实现接口
        public void Sort(int[] array)
        {
            int n = array.Length;
            for (int i = 0; i < n - 1; i++)
            {
                for (int j = 0; j < n - i - 1; j++)
                {
                    if (array[j] > array[j + 1])
                    {
                        // 交换元素
                        int temp = array[j];
                        array[j] = array[j + 1];
                        array[j + 1] = temp;
                    }
                }
            }
        }
    }
}
`
	expected := `namespace consoleTest
public class BubbleSort : ISort
public BubbleSort()
public void Sort(int[] array)
int n = array.Length;
for (int i = 0; i < n - 1; i++)
for (int j = 0; j < n - i - 1; j++)
if (array[j] > array[j + 1])
int temp = array[j];
array[j] = array[j + 1];
array[j + 1] = temp;`
	processor := NewCSharpPreprocessor()
	got := processor.ProcessContent(src)
	assert.Equal(t, expected, got)
}

func BenchmarkCSharpPreprocessor_ProcessContent(b *testing.B) {
	src := `using System;
namespace consoleTest
{
	public class BubbleSort : ISort
    {
		public BubbleSort()
		{
		}

        //实现接口
        public void Sort(int[] array)
        {
            int n = array.Length;
            for (int i = 0; i < n - 1; i++)
            {
                for (int j = 0; j < n - i - 1; j++)
                {
                    if (array[j] > array[j + 1])
                    {
                        // 交换元素
                        int temp = array[j];
                        array[j] = array[j + 1];
                        array[j + 1] = temp;
                    }
                }
            }
        }
    }
}
`
	processor := NewCSharpPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(src)
	}
}
