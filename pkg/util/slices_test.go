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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceSort(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want []int
	}{
		{
			"case-int-empty",
			[]int{},
			[]int{},
		},
		{
			"case-int-normal",
			[]int{1, 3, 2, 4},
			[]int{1, 2, 3, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceSort(tt.arg, func(i, j int) bool { return i < j })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceMap(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want []string
	}{
		{
			"case-int-empty",
			[]int{},
			[]string{},
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			[]string{"1", "2", "3", "4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceMap(tt.arg, strconv.Itoa)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceFlatMap(t *testing.T) {
	tests := []struct {
		name string
		arg  [][]int
		want []string
	}{
		{
			"case-int-empty",
			[][]int{},
			[]string{},
		},
		{
			"case-int-normal",
			[][]int{{1, 2}, {3, 4}},
			[]string{"1", "2", "3", "4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceFlatMap(tt.arg, func(it []int) []string {
				return SliceMap(it, strconv.Itoa)
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceFilter(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want []int
	}{
		{
			"case-int-empty",
			[]int{},
			[]int{},
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			[]int{1, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceFilter(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceAny(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want bool
	}{
		{
			"case-int-empty",
			[]int{},
			false,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceAny(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceAll(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want bool
	}{
		{
			"case-int-empty",
			[]int{},
			true,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceAll(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceNone(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want bool
	}{
		{
			"case-int-empty",
			[]int{},
			true,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceNone(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceFirst(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want int
	}{
		{
			"case-int-empty",
			[]int{},
			-1,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceFirst(tt.arg, func(i int) bool { return i%2 == 0 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceLast(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want int
	}{
		{
			"case-int-empty",
			[]int{},
			-1,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceLast(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceCount(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want int
	}{
		{
			"case-int-empty",
			[]int{},
			0,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceCount(tt.arg, func(i int) bool { return i%2 == 1 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceGroup(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want map[int][]int
	}{
		{
			"case-int-empty",
			[]int{},
			map[int][]int{},
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			map[int][]int{
				1: {1, 3},
				0: {2, 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceGroup(tt.arg, func(i int) int { return i % 2 })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceToMap(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want map[int]int
	}{
		{
			"case-int-empty",
			[]int{},
			map[int]int{},
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			map[int]int{
				1: 4,
				0: 6,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceToMap(tt.arg, func(i int) int { return i % 2 }, func(i int) int { return i }, func(i, j int) int { return i + j })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceReduce(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want int
	}{
		{
			"case-int-empty",
			[]int{},
			0,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceReduce(tt.arg, 0, func(i, j int) int { return i + j })
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceEach(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want []int
	}{
		{
			"case-int-empty",
			[]int{},
			[]int{},
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			[]int{2, 3, 4, 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make([]int, 0, len(tt.arg))
			SliceEach(tt.arg, func(i int) {
				got = append(got, i+1)
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceContains(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want bool
	}{
		{
			"case-int-empty",
			[]int{},
			false,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceContains(tt.arg, 3)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSliceEqual(t *testing.T) {
	tests := []struct {
		name string
		arg  []int
		want bool
	}{
		{
			"case-int-empty",
			[]int{},
			false,
		},
		{
			"case-int-normal",
			[]int{1, 2, 3, 4},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SliceEqual(tt.arg, []int{1, 2, 3, 4}, func(i, j int) bool { return i == j })
			assert.Equal(t, tt.want, got)
		})
	}
}
