// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package digester

import "testing"

func BenchmarkEnhancedSimHash64(b *testing.B) {
	tests := []struct {
		name string
		text string
	}{
		{
			name: "one line",
			text: "hello world",
		},
		{
			name: "multi lines",
			text: `import com.example.test;
			public class Test1{
			public int add1(int a1, int b1) {
				return a1 + b1;
			}
			public void main(String []args1){
				int sum = add1(1,2);
				System.out.println(("sum1=" + sum1);
			}
			}`,
		},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				EnhancedSimHash64([]byte(test.text))
			}
		})
	}
}
