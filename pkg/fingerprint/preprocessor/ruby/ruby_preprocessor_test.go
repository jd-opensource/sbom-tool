// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ruby

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
		"single line",
		`# single line
	         $global_variable = 10`,
		`$global_variable = 10`,
	},
	{
		"inline",
		`$global_variable = 10 # inline`,
		`$global_variable = 10`,
	},
	{
		"multiline",
		`=begin
	      multiline 1
          multiline 2
		=end
		$global_variable = 10`,
		`$global_variable = 10`,
	},
}

var testRubyCode = `#!/usr/bin/ruby
$LOAD_PATH << '.'
require "support"
module WeekXX
   FIRST_DAYXX = "Sunday"
   def WeekXX.weeks_in_month
      puts "You have four weeks in a month"
   end
   def WeekXX.weeks_in_year
      puts "You have 52 weeks in a year"
   end
end
class DecadeXX
include WeekXX
   no_of_yrs=10
   def no_of_months
      puts WeekXX::FIRST_DAYXX
      number=10*12
      puts number
   end
end
d1=DecadeXX.new
puts WeekXX::FIRST_DAYXX
Week.weeks_in_month
Week.weeks_in_year
d1.no_of_months`

func TestRemoveComment(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			processor := NewRubyPreprocessor()
			actual := processor.ProcessContent(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func TestRubyPreprocessor_ProcessContent(t *testing.T) {
	expected_code := `$LOAD_PATH << '.'
module WeekXX
FIRST_DAYXX = "Sunday"
def WeekXX.weeks_in_month
puts "You have four weeks in a month"
def WeekXX.weeks_in_year
puts "You have 52 weeks in a year"
class DecadeXX
include WeekXX
no_of_yrs=10
def no_of_months
puts WeekXX::FIRST_DAYXX
number=10*12
puts number
d1=DecadeXX.new
puts WeekXX::FIRST_DAYXX
Week.weeks_in_month
Week.weeks_in_year
d1.no_of_months`
	processor := NewRubyPreprocessor()
	actual := processor.ProcessContent(testRubyCode)
	assert.Equal(t, expected_code, actual)
}

func BenchmarkRubyPreprocessor_ProcessContent(b *testing.B) {
	processor := NewRubyPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(testRubyCode)
	}
}
