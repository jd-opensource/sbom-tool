## 开发指南


## 开发环境

### 开发工具
- Go 1.18 及以上 https://go.dev/dl/
- Goland https://www.jetbrains.com/go/
- VSCode https://code.visualstudio.com/
- golangci-lint https://golangci-lint.run/usage/install/

## 代码规范

### 编码规范
#### 日志输出规范
- Infof  输出info级别日志
- Warnf  输出warn级别日志
- Errorf  输出error级别日志，并输出堆栈信息，用于程序出现异常，但能继续执行
- Fatalf  输出fatal级别日志，并输出堆栈信息，执行os.Exist(1) ，用于程序出现异常，不能继续执行
- Debugf  输出debug级别日志
- Quietf  输出info级别日志，在quiet模式下也会输出到控制台，用于quiet模式下输出并要信息
#### 程序退出码
- 0    程序正常退出，处理正常完成、采集正常完成等情况
- 1    程序非正常退出，如参数错误、文件不存在、其他错误等无法继续执行等情况
- 为了方便，可以直接使用log.Fatalf输出错误日志并退出
#### 开发风格规范
- [Uber Go 语言编码规范](https://github.com/xxjwxc/uber_go_guide_cn)
#### 代码格式检查
- 建议在代码提交前执行`make format`规范您的代码风格


### 代码扫描
```shell
golangci-lint run # 启用默认规则，规则较少
golangci-lint run --enable-all # 启用全部规则，规则太多
```

## 测试要求

### 单元测试要求
- 测试命名：使用清晰、描述性的名称来命名测试函数，以便于理解测试的目的。
- 测试覆盖率：尽可能覆盖代码中的各个分支和边界条件，确保测试覆盖尽可能全面。
- 独立性：确保每个测试函数都是相互独立的，不会相互影响。
- 可读性：编写易于理解和维护的测试代码，使用适当的断言和注释。
- 快速执行：测试应该尽量快速执行，避免过长的测试时间。


### 性能测试要求
- 目标设定：明确性能测试的目标，例如响应时间、吞吐量等指标。
- 数据准备：准备适当的测试数据，包括模拟真实环境的数据量和负载。
- 测试环境：在与实际部署环境相似的环境中进行性能测试，确保结果更加准确可靠。
- 测试工具：选择适合的性能测试工具，并配置正确的测试参数。
- 测试报告：记录和分析性能测试结果，包括性能指标、瓶颈分析和建议的优化措施。

### 单测覆盖率命令执行
```shell
# 更新工具版本
go install github.com/axw/gocov/gocov@latest
go install github.com/AlekSi/gocov-xml@latest
# 执行编译
go mod tidy
# 执行单元测试
go test  ./...  -v -coverprofile=cover.out
# 生成单元测试报告及覆盖率
go tool cover -html=cover.out -o coverage.html 
gocov convert cover.out | gocov-xml > coverage.xml
```

## 代码指纹扩展

1. 实现解析器接口 PreProcessor接口，各个语言的预处理器需要实现PreProcessor接口，实现方法:
- Name：预处理器的名称，如 java、cpp等，唯一
- SupportedFileTypes：预处理器支持的文件类型，文件后缀列表，如 .cpp/.hpp/.c/.c
- ProcessContent：处理指定文件，返回处理后的内容
```go
 type PreProcessor interface {
    Name() string               // 预处理器唯一ID名称，例如 cpp、java、python等
    ProcessContent(content string) string // 处理文件内容，移除非关键信息是算法更准确
    SupportedFileTypes() []string // 支持的文件类型，文件后缀名，用于匹配预处理器，如.c、.h、.cpp、.java
 }
```
2. preprocessors.go中注册预处理器实例到全局预处理器容器
```go
func AllPreProcessors() []preprocessor.PreProcessor {
return []preprocessor.PreProcessor{
cpp.NewCppPreprocessor(),
}
}
```   


## 依赖扫描扩展
1. 按照包管理器进行分类，实现对应的采集器接口 Collector
```go
type Collector interface {
	GetName() string
	GetPurlType() string
	GetParsers() []FileParser
	TryToAccept(file File)
	GetRequests() []Request
	Collect() (pkgs []model.Package, err error)
}
```
2. 按照包管理器描述文件进行分类，实现对应的文件解析器接口 FileParser，并在采集器中注册
- Matcher：框架根据FileMatcher中的不同文件匹配方法，匹配对应待扫描文件
- Parse：解析指定文件，返回包信息和依赖信息
```go
type FileParser interface {
    Matcher() FileMatcher
    Parse(path string) (pkgs []model.Package, err error)
}
```

3. 通过对应包管理器内collector.go初始化一个或多个文件解析方法，创建解析器实例
```go
func init() {
	pckg.RegisterPackageParser(NewXxxFileParser())
	pckg.RegisterPackageParser(NewYyyFileParser())
}
```

4. 通过collectors.go完成各个包管理解析器实例的注册
```go
func AllCollectors() []collector.Collector {
var allCollectors []collector.Collector
allCollectors = append(allCollectors, cargo.NewCollector())
allCollectors = append(allCollectors, carthage.NewCollector())
return allCollectors
}
```

## 文档规范扩展
1. 实现文档规范接口 Spec 和 Format
```go
// Spec is a sbom specfication
type Spec interface {
Name() string        // Name returns the spec name
Version() string     // Version returns the spec version
Validate() error     // Validate validates the spec
Formats() []Format   // Formats returns all formats of this spec
FromSBOM(*sbom.SBOM) // FromSBOM converts a sbom to spec
ToSBOM() *sbom.SBOM  // ToSBOM converts spec to a sbom
Updaters() []Updater //
}

// Format is a sbom file format
type Format interface {
Spec() Spec                  // Spec returns the spec of this format
Type() string                // Type returns the format type
Load(reader io.Reader) error // Load loads a sbom from reader
Dump(writer io.Writer) error // Dump dumps a sbom to writer
}
```
2. 解析器init中调用RegisterPackageParser注册解析器实例到全局解析器容器
```go
func init() {
	s := &SpdxSpec{}
	s.formats = []spec.Format{
		&JsonFormat{spec: s},
		&TagValueFormat{spec: s},
	}
	spec.Register(s)
}
```
3. 在specifications.go中创建对应的文档清单，完成文档注册
```go
func AllSpecifications() []format.Specification {
return []format.Specification{
spdx.NewSpecification(),
}
}
```