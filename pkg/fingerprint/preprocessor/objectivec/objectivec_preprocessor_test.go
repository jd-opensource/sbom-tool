// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package objectivec

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
	         aaa = "John";`,
		`aaa = "John";`,
	},
	{
		"single line 2",
		`//这是一个单行注释
              bbb = "John";`,
		`bbb = "John";`,
	},
	{
		"inline 1",
		`ccc = "John"; // 设置变量 $name`,
		`ccc = "John";`,
	},
	{
		"multiline 1",
		`/*
			这是一个多行注释
			可以跨越多行
			*/
            ddd = "John";`,
		`ddd = "John";`,
	},
	{
		"multiline 2",
		`/**
			 * 这是一个函数的文档注释
			 *
			 * @param string $name 用户名
			 * @return string 欢迎消息
			 */
             eee = "John";`,
		`eee = "John";`,
	},
}

var testObjectivecCode = `#import "ZXQRCodeReader.h"
#import "ZXResult.h"

@implementation ZXQRCodeReader

// 这是一个单行注释
int x = 10; // 定义一个整数变量x并赋值为10

/**
这是一个文档注释
用于生成API文档说明
@param x 输入的整数
@return 两倍于输入整数的结果
*/
- (int)doubleInteger:(int)x {
    return x * 2;
}

/*
这是一个多行注释
可以使用多行注释来注释多行代码
int x = 10;
int y = 20;
*/

- (float)moduleSize:(ZXIntArray *)leftTopBlack image:(ZXBitMatrix *)image {
  BOOL inBlackAA = YES;
  int transitionsBB = 0;
  while (x < widthCC && y < heightDD) {
    if (inBlackAA != [image getX:x y:y]) {
      if (++transitionsBB == 5) {
        break;
      }
      inBlackAA = !inBlackAA;
    }
    x++;
    y++;
  }
  if (x == widthCC || y == heightDD) {
    return -1;
  }

  return (x - leftTopBlack.array[0]) / 7.0f;
}

@end
`

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			processor := NewObjectivecPreprocessor()
			actual := processor.ProcessContent(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestObjectivecPreprocessor_ProcessContent(t *testing.T) {
	expected_code := `int x = 10;
- (int)doubleInteger:(int)x {
return x * 2;
- (float)moduleSize:(ZXIntArray *)leftTopBlack image:(ZXBitMatrix *)image {
BOOL inBlackAA = YES;
int transitionsBB = 0;
if (inBlackAA != [image getX:x y:y]) {
if (++transitionsBB == 5) {
inBlackAA = !inBlackAA;
x++;
y++;
if (x == widthCC || y == heightDD) {
return -1;
return (x - leftTopBlack.array[0]) / 7.0f;`
	processor := NewObjectivecPreprocessor()
	actual := processor.ProcessContent(testObjectivecCode)
	assert.Equal(t, expected_code, actual)
}

func BenchmarkObjectivecPreprocessor_ProcessContent(b *testing.B) {
	processor := NewObjectivecPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testObjectivecCode)
	}
}
