// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMD5Sum(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			"case-string-empty",
			"",
			"d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			"case-string-normal",
			"hello world",
			"5eb63bbbe01eeed093cb22bb8f5acdc3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := MD5SumStr(tt.arg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSHA1Sum(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			"case-string-empty",
			"",
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			"case-string-normal",
			"hello world",
			"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := SHA1SumStr(tt.arg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSHA256Sum(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			"case-string-empty",
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"case-string-normal",
			"hello world",
			"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := SHA256SumStr(tt.arg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSM3Sum(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			"case-string-empty",
			"",
			"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		},
		{
			"case-string-normal",
			"hello world",
			"44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := SM3SumStr(tt.arg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVerifyCode(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"case-empty",
			[]string{},
			"",
		},
		{
			"case-emptyline",
			[]string{""},
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			"case-oneline",
			[]string{"hello world"},
			"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
		},
		{
			"case-multiline",
			[]string{"hello", "world"},
			"7db827c10afc1719863502cf95397731b23b8bae",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyCode(tt.args, func(s string) string { return s })
			assert.Equal(t, tt.want, got)
		})
	}
}
