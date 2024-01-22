// Copyright 2023 Jingdong Technology Information Technology Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lua

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var comments = []struct {
	name     string
	code     string
	expected string
}{
	{
		"single line 1",
		`-- test
	         CC = cfg.variables.CC`,
		`CC = cfg.variables.CC`,
	},
	{
		"inline 1",
		`build = rockspec.build -- 设置变量 $name`,
		`build = rockspec.build`,
	},
	{
		"multiline 1",
		`--[[
					print("整段注释")
					print("整段注释")
					print("整段注释")
               --]]
             name4 = "John"`,
		`name4 = "John"`,
	},
	{
		"multiline 2",
		`--[=[
					print("整段注释，=号个数随意")
					print("整段注释，=号个数随意")
					print("整段注释，=号个数随意")
               --]=]
             name5 = "John"`,
		`name5 = "John"`,
	},
}

var testLuaCode = `-----------------------------

local fs = require("luarocks.fs")
--print("单行注释")
    local env = {
      CC = cfg.variables.CC,
      --LD = cfg.variables.LD,
      --CFLAGS = cfg.variables.CFLAGS,
   }

   if build.build_command then
      util.printout(build.build_command)
      if not fs.execute_env(env, build.build_command) then
         return nil, "Failed building."
      end
   end
---print("单行注释")

print("hello") --我是单行注释

--[[
print("整段注释")
print("整段注释")
print("整段注释")
--]]
 
 
--[=[
print("整段注释，=号个数随意")
print("整段注释，=号个数随意")
print("整段注释，=号个数随意")
--]=]
 
 
---[[
print("取消段注释，只需加个-")
--]]
`

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			processor := NewLuaPreprocessor()
			actual := processor.ProcessContent(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestLuaPreprocessor_ProcessContent(t *testing.T) {
	expected_code := `CC = cfg.variables.CC,
if build.build_command then
util.printout(build.build_command)
if not fs.execute_env(env, build.build_command) then
return nil, "Failed building."`
	processor := NewLuaPreprocessor()
	actual := processor.ProcessContent(testLuaCode)
	assert.Equal(t, expected_code, actual)
}

func BenchmarkLuaPreprocessor_ProcessContent(b *testing.B) {
	processor := NewLuaPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testLuaCode)
	}
}
