## user guide


## global subcommand

```shell
Usage:
  sbom-tool [command]

Available Commands:
  artifact    collect artifact information
  assembly    assembly sbom document from document segments
  completion  Generate the autocompletion script for the specified shell
  convert     convert sbom document format
  env         build environment info
  generate    generate sbom document
  help        Help about any command
  info        get tool introduction information
  modify      modify sbom document properties
  package     collect package dependencies
  source      collect source code information
  validate    validate sbom document format

Flags:
  -h, --help               help for sbom-tool
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
  -v, --version            version for sbom-tool

Use "sbom-tool [command] --help" for more information about a command.
```

## Subcommands

### source
collect source code information(include code fingerprint)
```
Usage:
  sbom-tool source [flags]

Examples:
sbom-tool source -m 4 -s /path/to/source  -o source.json --output-mode singlefile --ignore-dirs .git

Flags:
  -h, --help                 help for source
      --ignore-dirs string   dirs to ignore, skip all dot dirs, split by comma. sample: node_modules,logs
  -l, --language string      specify language(sample: java,cpp) (default "*")
  -o, --output string        output file (default "source.json")
      --output-mode string   output mode, singlefile or multiplefile (default "singlefile")
  -m, --parallelism int      number of parallelism (default 8)
  -p, --path string          project root path(use source path if empty)
  -s, --src string           project source directory(use project root if empty) (default ".")

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output

```

### package
collect package dependencies
```shell
Usage:
  sbom-tool package [flags]

Examples:
sbom-tool package -m 4 -p /path/to/project -o package.json

Flags:
  -h, --help              help for package
  -o, --output string     output file (default "package.json")
  -m, --parallelism int   number of parallelism (default 8)
  -p, --path string       project root path (default ".")

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output

```
### artifact
collect artifact information
```shell
Usage:
  sbom-tool artifact [flags]

Examples:
sbom-tool artifact -m 4 -d /path/to/dist -o artifact.json -n app -v 1.0 -u company 

Flags:
  -d, --dist string       distribution dir or artifact file (default ".")
  -h, --help              help for artifact
  -n, --name string       package name of artifact
  -o, --output string     output file (default "artifact.json")
  -m, --parallelism int   number of parallelism (default 8)
  -u, --supplier string   package supplier of artifact
  -v, --version string    package version of artifact

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
```
### generate
generate SBOM document
```shell
Usage:
  sbom-tool generate [flags]

Examples:
sbom-tool generate -m 4 -p /path/to/project -s /path/to/source -d /path/to/dist -l java -o sbom.spdx.json -f spdx-json --ignore-dirs .git  -n app -v 1.0 -u company -b https://example.com/sbom/xxx

Flags:
  -d, --dist string          distribution directory (default "./dist")
  -f, --format string        sbom document format (default "spdx-json")
  -h, --help                 help for generate
      --ignore-dist string   dirs to ignore for dist, skip all dot dirs, split by comma. sample: node_modules,logs
      --ignore-pkg string    dirs to ignore for package, skip all dot dirs, split by comma. sample: node_modules,logs
      --ignore-src string    dirs to ignore for source, skip all dot dirs, split by comma. sample: node_modules,logs
  -l, --language string      specify language(sample: java,cpp) (default "*")
  -n, --name string          package name of artifact
  -b, --namespace string     document namespace base uri
  -o, --output string        distribution directory
  -m, --parallelism int      number of parallelism (default 8)
  -p, --path string          project root path (default ".")
  -s, --src string           project source directory(use project root if empty) (default ".")
  -u, --supplier string      package supplier of artifact
  -v, --version string       package version of artifact

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
```
### assembly
assembly SBOM document from document segments
```shell
Usage:
  sbom-tool assembly [flags]

Examples:
sbom-tool assembly -p /path/to/segments -o sbom.spdx.json -f spdx-json

Flags:
  -f, --format string      sbom document format (default "spdx-json")
  -h, --help               help for assembly
  -b, --namespace string   document namespace base uri
  -o, --output string      distribution directory
  -p, --path string        sbom segments dir (default ".")

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
```
### convert
convert SBOM document format
```shell
Usage:
  sbom-tool convert [flags]

Examples:
sbom-tool convert -i /path/to/sbom -g xspdx-json -f spdx-json -o sbom.spdx.json

Flags:
  -f, --format string     the sbom document format convert to
  -h, --help              help for convert
  -i, --input string      input sbom document
  -g, --original string   the sbom document format convert from
  -o, --output string     output sbom document

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/Users/zhangzhenyu/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
```
 
### validate
validate SBOM document format
```shell
Usage:
  sbom-tool validate [flags]

Examples:
sbom-tool validate -i /path/to/sbom -f spdx-json -o result.json

Flags:
  -f, --format string   the sbom document format to validate
  -h, --help            help for validate
  -i, --input string    input sbom document
  -o, --output string   output result to file

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/Users/zhangzhenyu/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output

```

### modify
Support the modification function of some specified fields
```shell
Usage:
  sbom-tool modify [flags]

Examples:
sbom-tool modify -i /path/to/sbom -f spdx-json -o sbom.spdx.json

Flags:
      --add-creator stringArray   add creator of document, example:{"creator":"name|email|domain","creatorType":"Person|Organization|Tool"} (for spdx); add creator of document, example:{"creator":"name|email|domain","creatorType":"Person|Organization|Tool"} (for xspdx)
  -f, --format string             the sbom document format modify to
  -h, --help                      help for modify
  -i, --input string              input sbom document
  -o, --output string             output sbom document
      --set-build stringArray     set properties of artifact.build, example:{"os":"CentOS","arch":"amd64","kernel":"Linux","builder":"","compiler":""} (for xspdx)

Global Flags:
      --log-level string   log level (default "info")
      --log-path string    log output path (default "/Users/zhangzhenyu/sbom-tool/sbom-tool.log")
  -q, --quiet              no console output
```

### Get tool introduction information
Tool introduction and list of supported coding languages, compilers, and SBOM document formats
```shell
Usage:
  sbom-tool info

Examples:
sbom-tool info
```

## Test

```shell
make test  # unit test
make bench # benchmark test
```
