// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package javascript

import "testing"

func TestJavascriptPreprocess_ProcessContent(t *testing.T) {
	type args struct {
		content string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "case-2",
			args: args{content: `function hanoi(n, from, to, via) {
				 if (n === 1) {
				   console.log("Move disk 1 from ${from} to ${to}");
				 } else { hanoi(n - 1, from, via, to);
				   console.log("Move disk ${n} from ${from} to ${to}");
				   hanoi(n - 1, via, to, from);
				 }
				}
		
				// Example usage
				hanoi(3, "A", "C", "B");`},
			want: `function hanoi(n, from, to, via) {
if (n === 1) {
console.log("Move disk 1 from ${from} to ${to}");
} else { hanoi(n - 1, from, via, to);
console.log("Move disk ${n} from ${from} to ${to}");
hanoi(n - 1, via, to, from);
hanoi(3, "A", "C", "B");`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ja := PreProcessor{}
			if got := ja.ProcessContent(tt.args.content); got != tt.want {
				t.Errorf("ProcessContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
