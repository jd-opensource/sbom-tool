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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"github.com/tjfoc/gmsm/sm3"
)

// MD5Sum returns the MD5 checksum of the given reader.
func MD5Sum(r io.Reader) (string, error) {
	m := md5.New()
	_, err := io.Copy(m, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}

// MD5SumStr returns the MD5 checksum of the given string.
func MD5SumStr(content string) (string, error) {
	r := strings.NewReader(content)
	return MD5Sum(r)
}

// MD5SumFile returns the MD5 checksum of the given file.
func MD5SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return MD5Sum(f)
}

// SHA1Sum returns the SHA1 checksum of the given reader.
func SHA1Sum(r io.Reader) (string, error) {
	m := sha1.New()
	_, err := io.Copy(m, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}

// SHA1SumStr returns the SHA1 checksum of the given string.
func SHA1SumStr(content string) (string, error) {
	r := strings.NewReader(content)
	return SHA1Sum(r)
}

// SHA1SumFile returns the SHA1 checksum of the given file.
func SHA1SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return SHA1Sum(f)
}

// SHA256Sum returns the SHA256 checksum of the given reader.
func SHA256Sum(r io.Reader) (string, error) {
	m := sha256.New()
	_, err := io.Copy(m, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}

// SHA256SumStr returns the SHA256 checksum of the given string.
func SHA256SumStr(content string) (string, error) {
	r := strings.NewReader(content)
	return SHA256Sum(r)
}

// SHA256SumFile returns the SHA256 checksum of the given file.
func SHA256SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return SHA256Sum(f)
}

// SM3Sum returns the SM3 checksum of the given reader.
// The SM3 algorithm is a hash algorithm promulgated by the Chinese government.
// For details, please refer to https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml
func SM3Sum(r io.Reader) (string, error) {
	m := sm3.New()
	_, err := io.Copy(m, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}

// SM3SumStr returns the SM3 checksum of the given string.
func SM3SumStr(content string) (string, error) {
	r := strings.NewReader(content)
	return SM3Sum(r)
}

// SM3SumFile returns the SM3 checksum of the given file.
func SM3SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return SM3Sum(f)
}

// VerifyCode returns the verification code(SHA1 checksum) of lines converted from items.
func VerifyCode[T any](items []T, line func(T) string) string {
	if len(items) == 0 {
		return ""
	}
	lines := strings.Builder{}
	length := len(items)
	for i := 0; i < length; i++ {
		l := line(items[i])
		if len(l) > 0 {
			lines.WriteString(l)
			if i < length-1 {
				lines.WriteString("\n")
			}
		}
	}
	sum, _ := SHA1SumStr(lines.String())
	return sum
}
