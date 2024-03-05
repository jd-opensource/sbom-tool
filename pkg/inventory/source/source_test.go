package source

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRepoUrl(t *testing.T) {

}
func TestNormalizeRepoUrl(t *testing.T) {

	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "normal",
			input:  "https://gitee.com/JD-opensource/sbom-tool.git",
			expect: "https://gitee.com/JD-opensource/sbom-tool.git",
		},
		{
			name:   "with-user",
			input:  "https://user:pswd@gitee.com/JD-opensource/sbom-tool.git",
			expect: "https://gitee.com/JD-opensource/sbom-tool.git",
		},
	}

	for i := 0; i < len(tests); i++ {
		test := tests[i]
		t.Run(test.name, func(tt *testing.T) {
			assert.Equal(t, test.expect, normalizeHttpUrl(test.input))
		})
	}
}
