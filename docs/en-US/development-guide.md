## Development guide


## Development environment

### Development tools
- Go 1.18 and above https://go.dev/dl/
- Goland https://www.jetbrains.com/go/
- VSCode https://code.visualstudio.com/
- golangci-lint https://golangci-lint.run/usage/install/

## Code specification

### Coding requirement
#### Log output specification
- Infof  Output info level log
- Warnf  Output warn level log
- Errorf  Output error level log，And output stack information for the program to encounter an exception, but continue to execute
- Fatalf  Output fatal level log，And output stack information, execute os.Exist (1), for program exception, can not continue execution
- Debugf  Output debug level log
- Quietf  Output info level log，It will also be output to the console in quiet mode for output in quiet mode and ask for information
#### Program exit code
- 0    Normal exit of the program, normal completion of processing, normal completion of collection, etc.
- 1    Program exits abnormally, such as parameter error, file does not exist, other errors can not continue execution, etc.
- For convenience, you can directly use log.Fatalf to output the error log and exit
#### Standard development style
- [Uber Go](https://github.com/uber-go/guide)
#### Code format check
- It is recommended to execute `make format` to standardize your code style before the code is submitted.


### Code scan
```shell
golangci-lint run # Enable default rules with fewer rules
golangci-lint run --enable-all # Enable all rules, too many rules
```

## Test requirements

### Unit test requirements
- Test Naming: Use clear and descriptive names for test functions to understand the purpose of the tests.
- Test Coverage: Aim to cover various branches and boundary conditions in the code to ensure comprehensive test coverage.
- Independence: Ensure that each test function is independent of others and does not impact each other.
- Readability: Write test code that is easy to understand and maintain, using appropriate assertions and comments.
- Fast Execution: Tests should execute as quickly as possible to avoid long testing times.


### Performance testing requirements
- Objective Setting: Clearly define the objectives of performance testing, such as response time, throughput, and other metrics.
- Data Preparation: Prepare appropriate test data, including simulating realistic data volumes and workloads.
- Testing Environment: Conduct performance testing in an environment that closely resembles the actual deployment environment to ensure more accurate and reliable results.
- Testing Tools: Choose suitable performance testing tools and configure the test parameters correctly.
- Test Reporting: Record and analyze the results of performance testing, including performance metrics, bottleneck analysis, and recommended optimization measures.

### Execution of single test coverage command
```shell
go install github.com/axw/gocov/gocov@latest
go install github.com/AlekSi/gocov-xml@latest
# Perform compilation
go mod tidy
# Perform unit tests
go test  ./...  -v -coverprofile=cover.out
# Generate unit test report and coverage
go tool cover -html=cover.out -o coverage.html 
gocov convert cover.out | gocov-xml > coverage.xml
```

## Code fingerprint extension

1. Implement the PreProcessor interface for the parser. Preprocessors for different languages need to implement the PreProcessor interface, which includes the following methods:
- Name: The name of the preprocessor, such as java, cpp, etc. This should be unique.
- SupportedFileTypes: The file types supported by the preprocessor, represented as a list of file extensions, such as .cpp/.hpp/.c/.c.
- ProcessContent: Processes the specified file and returns the processed content.
```go
 type PreProcessor interface {
    Name() string             
    ProcessContent(content string) string 
    SupportedFileTypes() []string 
 }
```
2. Register the preprocessor instance in preprocessors.go to the global preprocessor container
```go
func AllPreProcessors() []preprocessor.PreProcessor {
return []preprocessor.PreProcessor{
cpp.NewCppPreprocessor(),
}
}
``` 

## Packages scanning extension
1. Classify according to the package manager and implement the corresponding collector interface Collector
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
2. Classify according to the package manager description file, implement the corresponding file parser interface **FileParser**, and register it in the collector
- Matcher: The framework matches corresponding scanned files according to different file matching methods in FileMatcher.
- Parse: Parses the specified file and returns package information and dependency information.
```go
type FileParser interface {
Matcher() FileMatcher
Parse(path string) (pkgs []model.Package, err error)
}
```

3. Create a parser instance by initializing one or more file parsing methods by collector.go in the corresponding package manager
```go
func init() {
	pckg.RegisterPackageParser(NewXxxFileParser())
	pckg.RegisterPackageParser(NewYyyFileParser())
}
```

4. Complete the registration of each package management parser instance through collectors.go
```go
func AllCollectors() []collector.Collector {
var allCollectors []collector.Collector
allCollectors = append(allCollectors, cargo.NewCollector())
allCollectors = append(allCollectors, carthage.NewCollector())
return allCollectors
}
```

## Document specification extension
1. Implement the document specification interfaces Spec and Format.
```go
// Spec is a sbom specfication
type Spec interface {
Name() string        // Name returns the spec name
Version() string     // Version returns the spec version
Validate() error     // Validate validates the spec
Formats() []Format   // Formats returns all formats of this spec
FromSBOM(*sbom.SBOM) // FromSBOM converts a sbom to spec
ToSBOM() *sbom.SBOM  // ToSBOM converts spec to a sbom
}

// Format is a sbom file format
type Format interface {
Spec() Spec                  // Spec returns the spec of this format
Type() string                // Type returns the format type
Load(reader io.Reader) error // Load loads a sbom from reader
Dump(writer io.Writer) error // Dump dumps a sbom to writer
}
```
2. In the init function of the parser, call RegisterPackageParser to register the parser instance to the global parser container.
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
3. Create the corresponding document list in specifications.go and complete the document registration
```go
func AllSpecifications() []format.Specification {
return []format.Specification{
spdx.NewSpecification(),
}
}
```