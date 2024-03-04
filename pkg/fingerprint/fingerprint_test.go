// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	tests = []struct {
		name     string
		input1   string
		input2   string
		distance uint8
	}{
		
		{
			name:     "prefix",
			input1:   "hello world",
			input2:   "hello",
			distance: 0x1a,
		},
		{
			name:     "suffix",
			input1:   "hello world",
			input2:   "world",
			distance: 0x21,
		},
		{
			name:     "include",
			input1:   "golang hello world",
			input2:   "hello",
			distance: 0x24,
		},
		{
			name:     "different",
			input1:   "golang",
			input2:   "hello",
			distance: 0x24,
		},
		{
			name: "long text",
			input1: `
import com.example.test;
public class Test1{
public int add1(int a1, int b1) {
	return a1 + b1;
}
public void main(String []args1){
	int sum = add1(1,2);
	System.out.println(("sum1=" + sum1);
}
}
`,
			input2: `

import com.example.test;
public class Test2{
public int add2(int a2, int b2) {
	return a2 + b2;
}
public void main(String []args2){
	int sum2 = add2(3,4);
	System.out.println("sum2=" + sum2);
}
}`,
			distance: 0x1a,
		},
	}
)

func TestCompare(t *testing.T) {
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.input1, tt.input2)
			assert.Equal(t, tt.distance, got)
		})
	}
}
