// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package swift

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSwiftPreprocessor_ProcessContent(t *testing.T) {
	src := `#if os(Linux)
#elseif os(macOS)
#endif
//
//  swiftdemo
//
import SwiftUI
@main
struct SwiftApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
`
	expected := `struct SwiftApp: App {
var body: some Scene {
WindowGroup {
ContentView()`
	processor := NewSwiftPreprocessor()
	got := processor.ProcessContent(src)
	assert.Equal(t, expected, got)
}

func BenchmarkSwiftPreprocessor_ProcessContent(b *testing.B) {
	src := `#if os(Linux)
#elseif os(macOS)
#endif
//
//  swiftdemo
//
import SwiftUI
@main
struct SwiftApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
`
	processor := NewSwiftPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(src)
	}
}
