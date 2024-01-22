// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package rust

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
		`// I’m feeling lucky today
    	 let lucky_number = 7;`,
		`
    	 let lucky_number = 7;`,
	},
	{
		"single line 2",
		`///I’m feeling lucky today
		 let lucky_number = 7;`,
		`
		 let lucky_number = 7;`,
	},
	{
		"inline 1",
		`let lucky_number = 7;//I’m feeling lucky today`,
		`let lucky_number = 7;`,
	},
	{
		"inline 2",
		`let lucky_number = 7;/*I’m feeling lucky today*/`,
		`let lucky_number = 7;`,
	},
	{
		"multiline 1",
		`/**
		  * I’m feeling lucky today
		  */
		 let lucky_number = 7;`,
		`
		 let lucky_number = 7;`,
	},
	{
		"comments combination",
		`let channel1 = channel.clone();
		 // let channel2 = channel.clone();
    	 req
      		.and_then(move |req| {
        		match req.method().clone() {
          			Method::Action(_) => Error::forbidden("not allowed! sorry."),
          			Method::Listen => channel1.handle(req),
          			_ => adapter.handle(req),
        			}
      			})
      			/* .and_then(move |reply| { util::send_from_reply(reply, channel2.deref()) }) */
		 });`,
		`let channel1 = channel.clone();
		 
    	 req
      		.and_then(move |req| {
        		match req.method().clone() {
          			Method::Action(_) => Error::forbidden("not allowed! sorry."),
          			Method::Listen => channel1.handle(req),
          			_ => adapter.handle(req),
        			}
      			})
      			
		 });`,
	},
}

func TestRemoveRsComments(t *testing.T) {
	for _, comment := range comments {
		comment := comment
		t.Run(comment.name, func(t *testing.T) {
			actual := removeComments(comment.code)
			assert.Equal(t, comment.expected, actual)
		})
	}
}

func BenchmarkRustPreprocessor_ProcessContent(b *testing.B) {
	src := `use rand;
	extern crate futures;

	//command 1
	fn main() {
    	let mut counter = 0;
    	/**
    		command 2
     	*/
    	let result = loop {
        	counter += 1;
        	if counter == 10 {
            	break counter * 2;
        	} else {
            	continue;
        	}
    	};
	}
`
	processor := NewRustPreprocessor()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessContent(src)
	}
}
