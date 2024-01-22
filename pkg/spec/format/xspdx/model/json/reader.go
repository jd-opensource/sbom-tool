// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package json

import (
	"bytes"
	"encoding/json"
	"io"

	"gitee.com/jd-opensource/sbom-tool/pkg/spec/format/xspdx/model"
)

func Read(content io.Reader) (*model.XSPDXDocument, error) {
	doc := model.XSPDXDocument{}
	err := ReadInto(content, &doc)
	return &doc, err
}

func ReadInto(content io.Reader, doc *model.XSPDXDocument) error {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(content)
	if err != nil {
		return err
	}

	err = json.Unmarshal(buf.Bytes(), &doc)
	if err != nil {
		return err
	}
	return nil
}
