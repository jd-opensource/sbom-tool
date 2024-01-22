// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package fingerprint

import (
	"strings"

	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/cpp"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/csharp"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/dart"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/golang"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/java"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/javascript"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/lua"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/objectivec"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/php"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/python"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/ruby"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/rust"
	"gitee.com/jd-opensource/sbom-tool/pkg/fingerprint/preprocessor/swift"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
)

func AllPreProcessors() []preprocessor.PreProcessor {
	return []preprocessor.PreProcessor{
		cpp.NewCppPreprocessor(),
		csharp.NewCSharpPreprocessor(),
		golang.NewGolangPreprocessor(),
		java.NewJavaPreprocessor(),
		javascript.NewJavascriptPreprocess(),
		php.NewPhpPreprocessor(),
		python.NewPythonPreprocessor(),
		ruby.NewRubyPreprocessor(),
		rust.NewRustPreprocessor(),
		swift.NewSwiftPreprocessor(),
		lua.NewLuaPreprocessor(),
		objectivec.NewObjectivecPreprocessor(),
		dart.NewDartPreprocessor(),
	}
}

func GetPreProcessors(languages string) []preprocessor.PreProcessor {
	allPreProcessors := AllPreProcessors()
	languages = strings.TrimSpace(languages)
	if languages == "" || languages == "*" {
		return allPreProcessors
	}
	languagesArr := strings.Split(languages, ",")
	languagesArr = util.SliceMap(languagesArr, func(lang string) string {
		return strings.TrimSpace(lang)
	})
	languagesArr = util.SliceFilter(languagesArr, func(name string) bool {
		return name != ""
	})
	return util.SliceFilter(allPreProcessors, func(processor preprocessor.PreProcessor) bool {
		return slices.Contains(languagesArr, processor.Name())
	})
}
