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

import (
	"bytes"
	"fmt"

	"github.com/spaolacci/murmur3"
)

const HashSize = 64

type Vector [HashSize]int

func (v Vector) toUint64() uint64 {
	var f uint64
	for i := uint8(0); i < 64; i++ {
		if v[i] >= 0 {
			f |= 1 << i
		}
	}
	return f
}

// EnhancedSimHash64 returns the enhanced simhash of the given data.
func EnhancedSimHash64(data []byte) string {
	return fmt.Sprintf("%x", enhancedSimHash64(data))
}

func enhancedSimHash64(data []byte) uint64 {
	// TODO newline by os
	lines := bytes.Split(data, []byte("\n"))
	vs := make([]Vector, len(lines))
	for i, line := range lines {
		vs[i] = digestToVector(line)
	}
	return sum(vs).toUint64()
}

func digestToVector(data []byte) Vector {
	var v Vector
	sum := murmur3.Sum64(data)
	for i := uint8(0); i < HashSize; i++ {
		bit := (sum >> i) & 1
		if bit == 1 {
			v[i]++
		} else {
			v[i]--
		}
	}
	return v
}

func sum(vs []Vector) Vector {
	var sum Vector
	for _, v := range vs {
		for i := 0; i < HashSize; i++ {
			sum[i] += v[i]
		}
	}
	return sum
}
