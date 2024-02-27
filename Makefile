# Build variables #################################
PROJECT_NAME := sbom-tool
BUILD_DIR := dist
GIT_TAG := $(shell git describe --tags --always)
BUILD_TIME := $(shell date '+%Y%m%d')
REPO := gitee.com/JD-opensource/sbom-tool
ROOT_PACKAGE := gitee.com
# Go variables ####################################
GO := go
CUR_OS :=  $(shell go env GOOS)
CUR_ARCH :=  $(shell go env GOARCH)


.PHONY: default
default:
	@make $(CUR_OS)

.PHONY: format
format: tool.verify.goimports-reviser
	@echo "===========> Formatting codes"
	gofmt -s -w .
	goimports-reviser -local $(ROOT_PACKAGE) -file-path . -recursive reviser
	$(GO) mod edit -fmt


.PHONY: license
license: tool.verify.addlicense
	@echo "===========> Adding licenses for source code"
	find . -name '*.go' -exec addlicense -f build/license_header.tpl -c "Jingdong Technology Information Technology Co., Ltd." {} \;

.PHONY: notice
notice: tool.verify.golicenses
	@echo "===========> Generating notice file for dependencies"
	go-licenses report ./... --ignore gitee.com/JD-opensource/sbom-tool --template build/notice.tpl > NOTICE

.PHONY: release
release: tool.verify.goreleaser
	goreleaser release --skip-publish

.PHONY: all
all: linux darwin windows

.PHONY: linux
linux:
	$(GO) mod tidy
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-linux-amd64 cmd/sbom-tool/main.go
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-linux-arm64 cmd/sbom-tool/main.go

.PHONY: darwin
darwin:
	$(GO) mod tidy
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-darwin-amd64 cmd/sbom-tool/main.go
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-darwin-arm64 cmd/sbom-tool/main.go

.PHONY: windows
windows:
	$(GO) mod tidy
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-windows-amd64.exe cmd/sbom-tool/main.go
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "-X $(REPO)/pkg/config.VERSION=$(GIT_TAG)-$(BUILD_TIME)-dev" -o bin/$(PROJECT_NAME)-windows-arm64.exe cmd/sbom-tool/main.go


.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf bin


.PHONY: test
test:
	go test -v -cover ./...


.PHONY: bench
bench:
	go test -v -bench='.' -run=none ./...


.PHONY: vet
vet:
	go vet ./...


.PHONY: tool.verify.%
tool.verify.%:
	@if ! which $* &>/dev/null; then $(MAKE) tool.install.$*; fi


.PHONY: tool.install.%
tool.install.%:
	@echo "===========> Installing $*"
	@$(MAKE) install.$*


.PHONY: install.goimports-reviser
install.goimports-reviser:
	@$(GO) install github.com/incu6us/goimports-reviser/v3@latest

.PHONY: install.goreleaser
install.goreleaser:
	@$(GO) install github.com/goreleaser/goreleaser@latest

.PHONY: install.addlicense
install.addlicense:
	@$(GO) install github.com/google/addlicense@latest

.PHONY: install.golicenses
install.golicenses:
	@$(GO) install github.com/google/go-licenses@latest


.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build            - Build the project,Output to bin directory for local testing"
	@echo "  release          - Use goreleaser build the project,Output to dist directory for official release"
	@echo "  format           - Standard code format"
	@echo "  license          - Add license for code"
	@echo "  notice           - Generate notice file for dependencies"
	@echo "  vet              - Perform code static diagnostics"
	@echo "  test             - Perform unit tests"
	@echo "  bench            - Perform a stress test"
	@echo "  clean            - Delete bin and dist directories"