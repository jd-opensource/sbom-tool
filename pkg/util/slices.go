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
	"reflect"
	"sort"
	"strings"
)

type sortwrapper[T any] struct {
	slice []T
	less  func(i, j T) bool
}

func (s *sortwrapper[T]) Len() int {
	return len(s.slice)
}

func (s *sortwrapper[T]) Less(i, j int) bool {
	return s.less(s.slice[i], s.slice[j])
}

func (s *sortwrapper[T]) Swap(i, j int) {
	s.slice[i], s.slice[j] = s.slice[j], s.slice[i]
}

// SliceSort sorts the slice in place using the less function.
func SliceSort[T any](in []T, less func(i, j T) bool) []T {
	sort.Sort(&sortwrapper[T]{slice: in, less: less})
	return in
}

// SliceMap maps the slice using the convert function.
func SliceMap[T any, R any](in []T, convert func(T) R) []R {
	ret := make([]R, len(in))
	for i := 0; i < len(in); i++ {
		ret[i] = convert(in[i])
	}
	return ret
}

// SliceFlatMap maps the slice using the convert function and flattens the result.
func SliceFlatMap[T any, R any](in []T, convert func(T) []R) []R {
	ret := make([]R, 0)
	for i := 0; i < len(in); i++ {
		ret = append(ret, convert(in[i])...)
	}
	return ret
}

// SliceFilter filters the slice using the filter function.
func SliceFilter[T any](in []T, filter func(T) bool) []T {
	ret := make([]T, 0)
	for i := 0; i < len(in); i++ {
		if filter(in[i]) {
			ret = append(ret, in[i])
		}
	}
	return ret
}

// SliceGroup groups the slice using the getKey function.
func SliceGroup[T any, K comparable](in []T, getKey func(T) K) map[K][]T {
	ret := make(map[K][]T)
	for i := 0; i < len(in); i++ {
		key := getKey(in[i])
		items, ok := ret[key]
		if !ok {
			items = make([]T, 0)
		}
		ret[key] = append(items, in[i])
	}
	return ret
}

// SliceToMap maps the slice using the getKey and getValue functions.
// If the key is already present, the combiner function is used to combine the values.
func SliceToMap[T any, K comparable, V any](in []T, getKey func(T) K, getValue func(T) V, combiner func(V, V) V) map[K]V {
	ret := make(map[K]V)
	for i := 0; i < len(in); i++ {
		key := getKey(in[i])
		value := getValue(in[i])
		oldValue, ok := ret[key]
		if ok {
			value = combiner(oldValue, value)
		}
		ret[key] = value
	}
	return ret
}

// SliceAll returns true if all elements match the test function.
func SliceAll[T any](in []T, test func(T) bool) bool {
	for i := 0; i < len(in); i++ {
		if !test(in[i]) {
			return false
		}
	}
	return true
}

// SliceAny returns true if any element matches the test function.
func SliceAny[T any](in []T, test func(T) bool) bool {
	for i := 0; i < len(in); i++ {
		if test(in[i]) {
			return true
		}
	}
	return false
}

// SliceNone returns true if no elements match the test function.
func SliceNone[T any](in []T, test func(T) bool) bool {
	for i := 0; i < len(in); i++ {
		if test(in[i]) {
			return false
		}
	}
	return true
}

// SliceFirst returns the index of the first element that matches the test function.
func SliceFirst[T any](in []T, test func(T) bool) int {
	for i := 0; i < len(in); i++ {
		if test(in[i]) {
			return i
		}
	}
	return -1
}

// SliceLast returns the index of the last element that matches the test function.
func SliceLast[T any](in []T, test func(T) bool) int {
	for i := len(in) - 1; i >= 0; i-- {
		if test(in[i]) {
			return i
		}
	}
	return -1
}

func SliceCount[T any](in []T, test func(T) bool) int {
	count := 0
	for i := 0; i < len(in); i++ {
		if test(in[i]) {
			count++
		}
	}
	return count
}

// SliceContains returns true if the slice contains the element.
func SliceContains[T comparable](in []T, target T) bool {
	return SliceContainsFunc(in, target, func(a, b T) bool { return a == b })
}

// SliceContainsFunc returns true if the slice contains the element using the equal function.
func SliceContainsFunc[T any](in []T, target T, equal func(T, T) bool) bool {
	for i := 0; i < len(in); i++ {
		if equal(in[i], target) {
			return true
		}
	}
	return false
}

// SliceEach iterates over the slice and calls the function for each element.
func SliceEach[T any](in []T, fn func(T)) {
	for i := 0; i < len(in); i++ {
		fn(in[i])
	}
}

// SliceReduce reduces the slice to a single value using the init value and the reduce function.
// The reduce function is called with the current value and the accumulator.
func SliceReduce[T any, R any](in []T, init R, fn func(T, R) R) R {
	ret := init
	for i := 0; i < len(in); i++ {
		ret = fn(in[i], ret)
	}
	return ret
}

// SliceEqual returns true if the two slices are equal.
// The equal function is used to compare the elements.
func SliceEqual[T any](in1 []T, in2 []T, equal func(T, T) bool) bool {
	len1 := len(in1)
	len2 := len(in2)
	if len1 != len2 {
		return false
	}
	for i := 0; i < len1; i++ {
		if !equal(in1[i], in2[i]) {
			return false
		}
	}
	return true
}

// SliceUnique returns a slice with unique elements.
// The combine function is used to combine the values.
func SliceUnique[T comparable](in []T) []T {
	return SliceUniqueFunc(in, func(t1 T, t2 T) T {
		return t1
	}, func(t1 T, t2 T) bool {
		return t1 == t2
	})
}

// SliceUniqueFunc returns a slice with unique elements.
// The combine function is used to combine the values.
// The equal function is used to determine if two elements are equal.
func SliceUniqueFunc[T any](in []T, combine func(T, T) T, equal func(T, T) bool) []T {
	ret := make([]T, 0)
	for i := 0; i < len(in); i++ {
		exist := false
		for j := 0; j < len(ret); j++ {
			if equal(ret[j], in[i]) {
				exist = true
				ret[j] = combine(ret[j], in[i])
			}
		}
		if !exist {
			ret = append(ret, in[i])
		}
	}
	return ret
}

// RemoveEmptyElements removes empty elements (nil or empty string) from the array and returns the resulting array.
func RemoveEmptyElements[T any](arr []T) []T {
	result := make([]T, 0, len(arr))

	for _, elem := range arr {
		if !isEmpty(elem) {
			result = append(result, elem)
		}
	}

	return result
}

// isEmpty checks if the given element is empty (nil or empty string).
func isEmpty(elem interface{}) bool {
	if elem == nil {
		return true
	}

	switch reflect.TypeOf(elem).Kind() {
	case reflect.String:
		return elem.(string) == "" || strings.TrimSpace(elem.(string)) == ""
	default:
		return false
	}
}
