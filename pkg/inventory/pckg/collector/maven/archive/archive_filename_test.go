// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package archive

import "testing"

func Test_parseJavaArchiveFilename(t *testing.T) {
	tests := []struct {
		name string
		args string
		want versionedFilename
	}{
		{
			name: "case-normal-1",
			args: "spruce.jar",
			want: versionedFilename{"spruce.jar", "spruce", ""},
		},
		{
			name: "case-normal-2",
			args: "spruce-util.jar",
			want: versionedFilename{"spruce-util.jar", "spruce-util", ""},
		},
		{
			name: "case-normal-3",
			args: "spruce-util-1.2.jar",
			want: versionedFilename{"spruce-util-1.2.jar", "spruce-util", "1.2"},
		},
		{
			name: "case-normal-4",
			args: "spruce-util-1.2-SNAPSHOT.jar",
			want: versionedFilename{"spruce-util-1.2-SNAPSHOT.jar", "spruce-util", "1.2-SNAPSHOT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseJavaArchiveFilename(tt.args)
			if got != tt.want {
				t.Errorf("Test_parseJavaArchiveFilename() got = %v, want %v", got, tt.want)
			}
		})
	}
}
