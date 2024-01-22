// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package license

import (
	"testing"
)

var licenseURLItem = []struct {
	licenseURL string
	expected   string
}{
	{
		"https://www.eclipse.org/legal/epl-2.0",
		"EPL-2.0",
	},
	{
		"http://glassfish.dev.java.net/public/CDDL+GPL_1_1",
		"CDDL-1.1;GPL-1.0-or-later",
	},
	{
		"http://repository.jboss.org/licenses/gpl-2.0-ce",
		"GPL-2.0-only",
	},
	{
		"https://www.gnu.org/licenses/old-licenses/lgpl-2.1-standalone",
		"LGPL-2.1-only",
	},
	{
		"www.opensource.org/licenses/Apache-2.0",
		"Apache-2.0",
	},
	{
		"https://www.apache.org/licenses/LICENSE-2.0",
		"Apache-2.0",
	},
	{
		"https://openjdk.java.net/legal/gplv2+ce",
		"GPL-2.0",
	},
	{
		"www.opensource.org/licenses/cpal_1.0",
		"CPAL-1.0",
	},
	{
		"www.opensource.org/licenses/bsd-license/",
		"BSD-3-Clause",
	},
}

var licenseNameItem = []struct {
	name     string
	expected string
}{
	{
		"Apache License, version 2.0",
		"Apache-2.0",
	},
	{
		"Eclipse Public License 2.0",
		"EPL-2.0",
	},
	{
		"GPL2 w/ CPE",
		"GPL-2.0",
	},
	{
		"MIT License",
		"MIT",
	},
	{
		"The MirOS Licence",
		"MirOS",
	},
}

var licenseFromContext = []struct {
	context  string
	expected string
}{
	{
		`    MIT License
	
	Copyright (c) Microsoft Corporation.
	
	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:
	
	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.
	
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE`,
		"MIT",
	},
	{
		`Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
   Copyright {}
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.`,
		"Apache-2.0",
	},
}

var licenseFromDirItem = []struct {
	dir      string
	expected []string
}{
	{
		"test_material/pro_1/",
		[]string{"Apache-2.0"},
	},
	{
		"test_material/pro_2/",
		[]string{"MIT"},
	},
	{
		"test_material/pro_3/",
		[]string{"MIT"},
	},
}

func TestGetLicenseByUrl(t *testing.T) {
	for _, item := range licenseURLItem {
		value, _, _ := ParseLicenseURL(item.licenseURL)
		if value != item.expected {
			t.Errorf("%v, expected %v got %v", item.licenseURL, item.expected, value)
		}
	}
}

func TestGetLicenseByName(t *testing.T) {
	for _, item := range licenseNameItem {
		value, _, _ := ParseLicenseName(item.name)
		if value != item.expected {
			t.Errorf("%v, expected %v got %v", item.name, item.expected, value)
		}
	}
}

func TestGetLicenseByContent(t *testing.T) {
	for _, item := range licenseFromContext {
		value, _, _ := ParseLicenseFromContent(item.context)
		if value != item.expected {
			t.Errorf("%v, expected %v got %v", item.context, item.expected, value)
		}
	}
}

func TestGetLicenseFromDir(t *testing.T) {
	for _, item := range licenseFromDirItem {
		value, _, _ := ParseLicenseFromDir(item.dir)
		if value[0] != item.expected[0] {
			t.Errorf("%v, expected %v got %v", value, item.expected, value)
		}
	}
}
