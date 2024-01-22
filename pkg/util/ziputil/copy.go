// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ziputil

import (
	"errors"
	"fmt"
	"io"
)

const (
	// represents the order of bytes
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)

const readLimit = 1 * GB

func SafeCopy(dst io.Writer, src io.Reader) error {
	num, err := io.Copy(dst, io.LimitReader(src, readLimit))
	if num >= readLimit || errors.Is(err, io.EOF) {
		return fmt.Errorf("file size over limit")
	}
	return nil
}
