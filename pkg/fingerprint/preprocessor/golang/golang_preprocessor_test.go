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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveComments(t *testing.T) {
	comments := []struct {
		name     string
		code     string
		expected string
	}{
		{
			"single line 1",
			`// 打印 hello world
		 fmt.Println("hello world")`,
			`
		 fmt.Println("hello world")`,
		},
		{
			"single line 2",
			`/// 打印 hello world
		 fmt.Println("hello world")`,
			`
		 fmt.Println("hello world")`,
		},
		{
			"inline 1",
			`fmt.Println("hello world") // 打印 hello world`,
			`fmt.Println("hello world") `,
		},
		{
			"inline 2",
			`fmt.Println("hello world") /* 打印 hello world */`,
			`fmt.Println("hello world") `,
		},
		{
			"multiline 1",
			`/**
		  * 打印 hello world 
		  */
		 fmt.Println("hello world") `,
			`
		 fmt.Println("hello world") `,
		},
	}

	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			actual := removeComments(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestImports(t *testing.T) {
	comments := []struct {
		name     string
		code     string
		expected string
	}{
		{
			"import 1",
			`import "fmt"
import "time"
fmt.Println(time.Now())`,
			"\n\nfmt.Println(time.Now())",
		},
		{
			"import 1",
			`import (
"fmt"
"time"
)
fmt.Println(time.Now())`,
			"\nfmt.Println(time.Now())",
		},
	}

	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			actual := removeImports(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestRemoveCommonKeywordLines(t *testing.T) {
	src := `package main
	
	import "fmt"
	
	func main() {
		fmt.Println("hello world")
	}`

	expected := `import "fmt"
func main() {
fmt.Println("hello world")`
	actual := removeCommonKeywordLines(src)

	assert.Equal(t, expected, actual)
}

func TestGolangPreprocessor_ProcessContent(t *testing.T) {
	src := `package main

import "fmt"
import (
	"time"
)

func main() {
	flag := 20
	/*
	打印成绩
	 */
	if flag < 60 {
		fmt.Println("poor")
	} else if flag < 80 {
		fmt.Println("good")
	} else {
		fmt.Println("excellent")
	}

	//print time
	printTime()
}

/*
*
打印当前时间
*/
func printTime() {
	fmt.Println(time.Now())
}
`
	expected := `func main() {
flag := 20
if flag < 60 {
fmt.Println("poor")
fmt.Println("good")
fmt.Println("excellent")
printTime()
func printTime() {
fmt.Println(time.Now())`
	processor := NewGolangPreprocessor()
	got := processor.ProcessContent(src)
	assert.Equal(t, expected, got)
}

func BenchmarkGolangPreprocessor_ProcessContent(b *testing.B) {
	src := `package main

	import "fmt"
	import (
		"time"
	)
	
	func main() {
		flag := 20
		/*
		打印成绩
		 */
		if flag < 60 {
			fmt.Println("poor")
		} else if flag < 80 {
			fmt.Println("good")
		} else {
			fmt.Println("excellent")
		}
	
		//print time
		printTime()
	}
	
	/*
	*
	打印当前时间
	*/
	func printTime() {
		fmt.Println(time.Now())
	}
	`
	processor := NewGolangPreprocessor()

	for i := 0; i < b.N; i++ {
		processor.ProcessContent(src)
	}
}
