# SBOM-TOOL
[English](./README.md) | 简体中文

SBOM-TOOL 是通过源码仓库、代码指纹、构建环境、制品信息、制品内容、依赖组建等多种维度信息，为软件项目生成软件物料清单（SBOM）的一款CLI工具。

## 功能特性

### 信息采集
- 采集源代码工程信息，包括仓库地址、版本信息等
- 采集并生成代码指纹，利用一定算法生成代码指纹
- 采集工程构建依赖环境信息，包括操作系统、内核、编译器、构建工具等
- 采集工程构建的依赖组件，支持多种语言、多种包管理器的依赖采集
- 采集最终制品包信息，包括包名、类型、唯一校验码等
- 采集制品内容信息，包括文件名类型、唯一校验码等
### SBOM文档
- 组装SBOM文档，基于上述采集的信息组装标准SBOM文档
- 规范格式转换，支持XSPDX、SPDX等规范，支持JSON等格式
- 规范格式校验，支持XSPDX、SPDX等规范，支持JSON等格式

## 代码指纹生成能力

| 开发语言          | 是否支持 |
|---------------|------|
| `C/C++`       | 是    | 
| `Java`        | 是  | 
| `C#`          | 是  | 
| `Dart`        | 是  | 
| `Golang`      | 是  | 
| `Javascript`  | 是  | 
| `Objective-C` | 是  | 
| `Php`         | 是  | 
| `Python`      | 是  | 
| `Ruby`        | 是  | 
| `Rust`        | 是  | 
| `Swift`       | 是  | 
| `Lua`         | 是  |


## 依赖包扫描能力


现已支持以下编程语言相关的配置文件解析、二进制包解析，后续会逐步支持更多的编程语言。

| 包类型                   | 包管理器                  | 解析文件                                                                                                                                                | 是否支持依赖图谱 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `maven`      | [Maven](https://maven.apache.org)                | <ul><li>`pom.xml`</li> <li>`*.jar`</li> <li>`*.war`</li><li>`[graph]maven-dependency-tree.txt(mvn dependency:tree -DoutputFile=maven-dependency-tree.txt)`</li></ul>                                                          | 是        |
| `maven`      | [Gradle](https://gradle.org)                     | <ul><li>`*.gradle`</li>  <li>`.gradle.lockfile`</li> <li>`[graph]gradle-dependency-tree.txt(gradlew gradle-baseline-java:dependencies > gradle-dependency-tree.txt)`</li></ul>                                                | 是        |
| `conan`      | [Conan](https://conan.io)                        | <ul><li>`conanfile.txt`</li> <li>`conan.lock`</li><li>`[graph]conan-graph-info.json(conan graph info -f json > conan-graph-info.json)`</li></ul>                                                                              | 是        |
| `npm`        | [NPM](https://www.npmjs.com)                     | <ul><li>`package.json`</li> <li>`package-lock.json`</li></ul>                                                                                                                                                                 | 否       |
| `npm`        | [Yarn](https://yarnpkg.com)                      | <ul><li>`[graph]yarn.lock`</li></ul>                                                                                                                                                                                          | 是        |
| `npm`        | [PNPM](https://pnpm.io/)                      | <ul><li>`[graph]pnpm.lock`</li></ul>                                                                                                                                                                                          | 是        |
| `golang`     | [Go Module](https://go.dev/ref/mod)              | <ul><li>`go.mod`</li>  <li>`Go Binary file`</li> <li>`[graph]go-mod-graph.txt(go mod graph > go-mod-graph.txt)` </li></ul>                                                                                                    | 是        |
| `golang`     | [Glide](https://github.com/Masterminds/glide)    | <ul><li>`glide.yml`</li> <li>`glide.yaml`</li></ul>                                                                                                                                                                           | 否       |
| `golang`     | [GoDep](https://github.com/tools/godep)          | <ul><li>`Godeps.json`  </li></ul>                                                                                                                                                                                             | 否       |
| `golang`     | [Dep](https://github.com/golang/dep)             | <ul><li>`Gopkg.toml` </li></ul>                                                                                                                                                                                               | 否       |
| `golang`     | [GVT](https://github.com/FiloSottile/gvt)        | <ul><li>`*/vendor/manifest`</li></ul>                                                                                                                                                                                         | 否       |
| `pypi`       | [PIP](https://pip.pypa.io)                       | <ul><li>`Pipfile.lock`</li>  <li>`*dist-info/METADATA`</li> <li>`PKG-INFO`</li> <li>`*requirements*.txt`</li> <li>`setup.py` </li><li>`[graph]pipenv-graph.txt(pipenv graph > pipenv-graph.txt)`</li></ul>                    | 是        |
| `pypi`       | [Poetry](https://python-poetry.org)              | <ul><li>`[graph]poetry.lock`</li></ul>                                                                                                                                                                                        | 是        |
| `conda`      | [Conda](https://conda.io)                        | <ul><li>`environment.yml`</li> <li>`environment.yaml`</li> <li>`package-list.txt`</li></ul>                                                                                                                                   | 否       |
| `composer`   | [Composer](https://getcomposer.org)              | <ul><li>`composer.json`</li> <li>`composer.lock`</li></ul>                                                                                                                                                                    | 否       |
| `cargo`      | [Cargo](https://doc.rust-lang.org/cargo)         | <ul><li>`Cargo.toml`</li> <li>`[graph]Cargo.lock`</li> <li>`Rust Binary file`</li></ul>                                                                                                                                              | 是        |
| `carthage`   | [Carthage](https://github.com/Carthage/Carthage) | <ul><li>`Cartfile`</li>   <li>`Cartfile.resolved`</li></ul>                                                                                                                                                                   | 否       |
| `swift`      | [SwiftPM](https://www.swift.org/package-manager) | <ul><li>`Package.swift`</li></ul>                                                                                                                                                                                             | 否       |
| `cocoapods`  | [Cocoapods](https://cocoapods.org)               | <ul><li>`Podfile.lock`</li><li>`Podfile`</li> <li>`*.podspec`</li></ul>                                                                                                                                                       | 是        |
| `gem`        | [Gem](https://rubygems.org)                      | <ul><li> `[graph]Gemfile.lock`</li><li>`Gemfile`</li> <li>`*.gemspec`</li></ul>                                                                                                                                                      | 是        |
| `nuget`      | [NuGet](https://www.nuget.org)                   | <ul><li>`[graph]*.deps.json`</li>   <li>`*.csproj`</li> <li>`*.vbproj`</li> <li>`*.fsproj`</li> <li>`*.vcproj`</li>  <li>`*.nuget.dgspec.json`</li> <li>`*.nuspec`</li> <li>`packages.json`</li> <li>`packages.lock.json` </li></ul> | 是        |
| `pub`        | [Pub](https://pub.dev)                           | <ul><li>`[graph]pub-deps.json(dart pub deps --json > pub-deps.json)`</li>   <li>`pubspec.lock`</li> <li>`pubspec.yaml`</li></ul>                                                                                                           | 是        |
| `rpm`        | [RPM](https://rpm-packaging-guide.github.io)     | <ul><li>`*.spec`</li></ul>                                                                                                                                                                                                    | 否       |
| `lua`        | [LuaRocks](https://luarocks.org)                 | <ul><li>`*.rockspec`</li></ul>                                                                                                                                                                                                | 否       |
| `bower`      | [Bower](https://bower.io)                        | <ul><li>`*.spec`</li></ul>                                                                                                                                                                                                    | 否        |


## 软件架构
![SBOM-TOOL整体架构](./docs/img/arch.png)



## 下载安装
1. 下载源码编译(需要 `go 1.18` 及以上版本)
   ```shell
   git clone git@gitee.com:JD-opensource/sbom-tool.git
   cd sbom-tool
   make
   ```
   默认生成多个系统架构的程序二进制包
    - Linux X86_64：sbom-tool-linux-amd64
    - Linux arm64：sbom-tool-linux-arm64
    - Windows X86_64：sbom-tool-windows-amd64.exe
    - Windows arm64：sbom-tool-windows-arm64.exe
    - MacOS amd64:  sbom-tool-darwin-amd64
    - MacOS arm64: sbom-tool-darwin-arm64

## 子命令说明


| 子命令 | 功能                 |
|----|--------------------|
| `help` | 工具帮助手册             | 
| `artifact` | 采集软件包制品信息          |
| `assembly` | 把各阶段生成的文档组装为SBOM文档 | 
| `completion` | 为指定的shell生成自动完成脚本  | 
| `convert` | 转换SBOM文档格式         | 
| `env` | 生成环境信息             |
| `generate` | 生成SBOM文档           |
| `package` | 收集包依赖项             | 
| `source` | 收集源代码信息            | 
| `validate` | 验证SBOM文档格式         | 
| `info`        | 获取工具介绍信息       | 
| `modify`        | 修改SBOM文档属性| 

## 参数说明

| 参数      | 短参数  | 描述                                                                                                | 使用样例                                       |
| --------- |------|---------------------------------------------------------------------------------------------------|--------------------------------------------|
| `--log-level `  |      | 指定日志级别，包括 `debug`、`info`、`warn`、`error`                                                                 | `--log-level info`                         |
| `--log-path `  |      | 指定日志路径，默认在用户主目录下自动生成日志目录及日志文件($home/sbom-tool/sbom-tool.log)                                      | `--log-path /tmp/sbom.log`                 |
| `--quiet  `  | `-q` | 无控制台输出                                                                                            | `--quiet`  </br>`-q`                       |
| `--ignore-dirs`   |      | 要忽略的目录，跳过所有点目录，以逗号分隔。示例：NODE_MODULES，LOGS                                                         | `--ignore-dirs log,logs`                   |
| `--language`  | `-l` | 指定语言(目前支持：`java`，`cpp`)(默认为“*”)                                                                       | `--language java`  </br>`-l cpp`           |
| `--parallelism`  | `-m` | 并发度(默认为`8`)                                                                                         | `--parallelism 4`  </br>`-m 9`             |
| `--output`  | `-o` | 指定结果输出文件存放路径及名称，默认会在当前目录下自动生成                                                                     | `--output /tmp/sbom.json`                  |
| `--src`  | `-s` | 指定源代码存放路径，默认为当前目录                                                                                 | `--src /tmp/sbomtool/src/`                 |
| `--path`  | `-p` | 指定项目工程主目录；assembly子命令中用于指定各阶段临时文档路径                             | `--path /tmp/sbomtool/`                    |
| `--dist `  | `-d` | 指定制品存放路径，默认为当前目录                                                                                  | `--dist /tmp/sbomtool/bin/`                |
| `--format`  | `-f` | 指定SBOM文档格式(目前支持：`xspdx-json`、`spdx-json`、`spdx-tagvalue`)(默认为`spdx-json`) | `--format spdx-json`  </br>`-f spdx-json` |
| `--input`  | `-i` | 指定SBOM文档作为输入                                                                                      | `--input /tmp/sbom.jsom`                   |
| `--algorithm`  | `-a` | 用于指定生成SBOM文档标识的算法(目前支持:`SHA1`、`SHA256`、`SM3`)(默认为`SM3`)                                                 | `--algorithm SHA256`                       |


## SBOM文档规范与格式

| 规范          | 格式         | SBOM文档格式         | 是否支持 |
|:------------|:-----------|:-----------------|:-----|
| `XSPDX`     | `JSON`     | `xspdx-json`     |已支持  |
| `SPDX`      | `JSON`     | `spdx-json`      |已支持    |
| `SPDX`      | `TagValue` | `spdx-tagvalue`  |已支持    |

`XSPDX 是基于SPDX扩展的SBOM格式规范`


## 使用示例


生成SBOM文档并指定格式

```shell
sbom-tool generate -m 4 -p ${project_path} -s ${src_path} -d ${dist_path}  -o sbom.spdx.json -f spdx-json --ignore-dirs .git  -n ${name} -v ${version} -u ${supplier} -b ${namespace}
```

获取工具介绍信息

```shell
sbom-tool info
```

更多使用案例，详见[文档](docs/zh-CN/user-guide.md)

## 开发指南
详见 [开发指南文档](docs/zh-CN/development-guide.md)

## 问题反馈&联系我们
如果在使用中遇到问题，欢迎您向我们提交ISSUE。


## 如何贡献
SBOM-TOOL 是一款开源的软件成分分析工具，期待您的贡献。

## 许可证
此项目是在 **MulanPSL2** 下授权的，有关详细信息，请参阅[许可证文件](LICENSE)。