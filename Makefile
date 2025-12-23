# veo Makefile
# 整合编译、优化和发布流程

# 项目配置
PROJECT_NAME := veo
VERSION ?= v1.0.0
BUILD_DIR := dist
RELEASE_DIR := release
BUILD_SCRIPT := ./build.sh
OUTPUT_DIR := $(BUILD_DIR)

# Go 编译配置
MAIN_FILE := ./cmd/main.go
GO_VERSION := $(shell go version | awk '{print $$3}')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date +"%Y-%m-%d_%H:%M:%S")

# Build Tags
# 默认构建：主动模式（不带 tag）
# 被动代理模式：go build -tags passive
PASSIVE_TAG := passive
PASSIVE_BUILD_DIR := $(BUILD_DIR)/passive
PASSIVE_RELEASE_DIR := $(RELEASE_DIR)/passive

# 编译标志
LDFLAGS := -s -w -buildid=
LDFLAGS += -X main.version=$(VERSION)
LDFLAGS += -X main.buildTime=$(BUILD_TIME)
LDFLAGS += -X main.gitCommit=$(GIT_COMMIT)
LDFLAGS += -X main.gitBranch=$(GIT_BRANCH)

BUILDFLAGS := -trimpath
GCFLAGS := all=-dwarf=false
ASMFLAGS := all=-trimpath=$(CURDIR)
CGO_ENABLED := 0

# 支持的平台
PLATFORMS := \
	windows/amd64 \
	windows/arm64 \
	windows/386 \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64

# 颜色输出
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# 默认目标
.DEFAULT_GOAL := help

# ============================================================================
# 帮助信息
# ============================================================================

.PHONY: help
help: ## 显示帮助信息
	@echo "$(BLUE)veo Makefile$(RESET)"
	@echo "=========================================="
	@echo ""
	@echo "$(GREEN)构建命令:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)示例:$(RESET)"
	@echo "  make build              # 编译当前平台（主动模式，默认）"
	@echo "  make build-passive      # 编译当前平台（被动代理模式，-tags passive）"
	@echo "  make build-both         # 同时编译主动+被动（当前平台）"
	@echo "  make build-all          # 编译所有平台（主动模式）"
	@echo "  make build-all-passive  # 编译所有平台（被动模式，输出到 dist/passive）"
	@echo "  make release            # 创建发布包"
	@echo "  make clean              # 清理构建文件"

# ============================================================================
# 清理命令
# ============================================================================

.PHONY: clean
clean: ## 清理所有构建文件
	@echo "$(BLUE)[CLEAN]$(RESET) 清理构建文件..."
	@rm -rf $(BUILD_DIR) $(RELEASE_DIR)
	@echo "$(GREEN)[SUCCESS]$(RESET) 清理完成"

.PHONY: clean-dist
clean-dist: ## 清理编译输出
	@echo "$(BLUE)[CLEAN]$(RESET) 清理编译输出..."
	@rm -rf $(BUILD_DIR)

.PHONY: clean-release
clean-release: ## 清理发布文件
	@echo "$(BLUE)[CLEAN]$(RESET) 清理发布文件..."
	@rm -rf $(RELEASE_DIR)

# ============================================================================
# 准备工作
# ============================================================================

.PHONY: deps
deps: ## 下载依赖包
	@echo "$(BLUE)[DEPS]$(RESET) 下载依赖包..."
	@go mod download
	@go mod tidy
	@echo "$(GREEN)[SUCCESS]$(RESET) 依赖包下载完成"

.PHONY: verify
verify: ## 验证依赖包
	@echo "$(BLUE)[VERIFY]$(RESET) 验证依赖包..."
	@go mod verify
	@echo "$(GREEN)[SUCCESS]$(RESET) 依赖包验证完成"

.PHONY: check
check: ## 检查代码
	@echo "$(BLUE)[CHECK]$(RESET) 检查代码..."
	@go vet ./...
	@go fmt ./...
	@echo "$(GREEN)[SUCCESS]$(RESET) 代码检查完成"

# ============================================================================
# 编译命令
# ============================================================================

.PHONY: build
build: deps ## 编译当前平台（主动模式，默认）
	@echo "$(BLUE)[BUILD]$(RESET) 编译当前平台（主动模式）..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) go build $(BUILDFLAGS) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(PROJECT_NAME) $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) 编译完成: $(BUILD_DIR)/$(PROJECT_NAME)"

.PHONY: build-passive
build-passive: deps ## 编译当前平台（被动代理模式，-tags passive）
	@echo "$(BLUE)[BUILD]$(RESET) 编译当前平台（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) go build $(BUILDFLAGS) -tags $(PASSIVE_TAG) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME) $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) 编译完成: $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME)"

.PHONY: build-both
build-both: build build-passive ## 同时编译主动+被动（当前平台）

.PHONY: build-all
build-all: ## 编译所有平台（主动模式）
	@echo "$(BLUE)[BUILD-ALL]$(RESET) 编译所有平台（主动模式）..."
	@VERSION=$(VERSION) ./build.sh -a

.PHONY: build-all-passive
build-all-passive: ## 编译所有平台（被动代理模式，输出到 dist/passive）
	@echo "$(BLUE)[BUILD-ALL]$(RESET) 编译所有平台（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@VERSION=$(VERSION) GOFLAGS="-tags=$(PASSIVE_TAG)" ./build.sh -a -o $(PASSIVE_BUILD_DIR)

.PHONY: build-all-both
build-all-both: build-all build-all-passive ## 编译所有平台（主动+被动）

.PHONY: build-windows
build-windows: ## 编译 Windows 平台（主动模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 Windows 平台（主动模式）..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 go build $(BUILDFLAGS) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(PROJECT_NAME)_windows_amd64.exe $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) Windows 编译完成"

.PHONY: build-windows-passive
build-windows-passive: ## 编译 Windows 平台（被动代理模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 Windows 平台（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 go build $(BUILDFLAGS) -tags $(PASSIVE_TAG) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME)_windows_amd64.exe $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) Windows 被动模式编译完成"

.PHONY: build-windows-both
build-windows-both: build-windows build-windows-passive ## 编译 Windows 平台（主动+被动）

.PHONY: build-linux
build-linux: ## 编译 Linux 平台（主动模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 Linux 平台（主动模式）..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build $(BUILDFLAGS) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(PROJECT_NAME)_linux_amd64 $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) Linux 编译完成"

.PHONY: build-linux-passive
build-linux-passive: ## 编译 Linux 平台（被动代理模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 Linux 平台（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build $(BUILDFLAGS) -tags $(PASSIVE_TAG) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME)_linux_amd64 $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) Linux 被动模式编译完成"

.PHONY: build-linux-both
build-linux-both: build-linux build-linux-passive ## 编译 Linux 平台（主动+被动）

.PHONY: build-darwin
build-darwin: ## 编译 macOS 平台（主动模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 macOS 平台（主动模式）..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 go build $(BUILDFLAGS) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(PROJECT_NAME)_darwin_amd64 $(MAIN_FILE)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 go build $(BUILDFLAGS) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(PROJECT_NAME)_darwin_arm64 $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) macOS 编译完成"

.PHONY: build-darwin-passive
build-darwin-passive: ## 编译 macOS 平台（被动代理模式）
	@echo "$(BLUE)[BUILD]$(RESET) 编译 macOS 平台（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 go build $(BUILDFLAGS) -tags $(PASSIVE_TAG) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME)_darwin_amd64 $(MAIN_FILE)
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 go build $(BUILDFLAGS) -tags $(PASSIVE_TAG) -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" -ldflags="$(LDFLAGS)" -o $(PASSIVE_BUILD_DIR)/$(PROJECT_NAME)_darwin_arm64 $(MAIN_FILE)
	@echo "$(GREEN)[SUCCESS]$(RESET) macOS 被动模式编译完成"

.PHONY: build-darwin-both
build-darwin-both: build-darwin build-darwin-passive ## 编译 macOS 平台（主动+被动）

# ============================================================================
# 优化命令
# ============================================================================

.PHONY: build-optimized
build-optimized: deps ## 编译优化版本（主动模式）
	@echo "$(BLUE)[BUILD-OPT]$(RESET) 编译优化版本（主动模式）..."
	@VERSION=$(VERSION) ./build.sh

.PHONY: build-optimized-passive
build-optimized-passive: deps ## 编译优化版本（被动代理模式，-tags passive）
	@echo "$(BLUE)[BUILD-OPT]$(RESET) 编译优化版本（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@VERSION=$(VERSION) GOFLAGS="-tags=$(PASSIVE_TAG)" ./build.sh -o $(PASSIVE_BUILD_DIR)

.PHONY: build-optimized-both
build-optimized-both: build-optimized build-optimized-passive ## 编译优化版本（主动+被动）

.PHONY: build-debug
build-debug: deps ## 编译调试版本（主动模式）
	@echo "$(BLUE)[BUILD-DEBUG]$(RESET) 编译调试版本（主动模式）..."
	@VERSION=$(VERSION) ./build.sh --with-debug

.PHONY: build-debug-passive
build-debug-passive: deps ## 编译调试版本（被动代理模式，-tags passive）
	@echo "$(BLUE)[BUILD-DEBUG]$(RESET) 编译调试版本（被动代理模式）..."
	@mkdir -p $(PASSIVE_BUILD_DIR)
	@VERSION=$(VERSION) GOFLAGS="-tags=$(PASSIVE_TAG)" ./build.sh --with-debug -o $(PASSIVE_BUILD_DIR)

.PHONY: build-debug-both
build-debug-both: build-debug build-debug-passive ## 编译调试版本（主动+被动）

.PHONY: compress
compress: ## UPX压缩现有二进制文件（包含 dist/ 与 dist/passive/）
	@echo "$(BLUE)[COMPRESS]$(RESET) 压缩二进制文件..."
	@if command -v upx >/dev/null 2>&1; then \
		for dir in $(BUILD_DIR) $(PASSIVE_BUILD_DIR); do \
			if [ ! -d "$$dir" ]; then continue; fi; \
			for file in "$$dir"/*; do \
				if [ -f "$$file" ] && [ -x "$$file" ]; then \
					echo "压缩: $$file"; \
					upx --best --lzma "$$file" 2>/dev/null || echo "跳过: $$file"; \
				fi; \
			done; \
		done; \
		echo "$(GREEN)[SUCCESS]$(RESET) 压缩完成"; \
	else \
		echo "$(YELLOW)[WARNING]$(RESET) UPX 未安装，跳过压缩"; \
	fi

# ============================================================================
# 测试命令
# ============================================================================

.PHONY: test
test: ## 运行测试（主动模式，默认）
	@echo "$(BLUE)[TEST]$(RESET) 运行测试（主动模式）..."
	@go test -v ./...

.PHONY: test-passive
test-passive: ## 运行测试（被动代理模式，-tags passive）
	@echo "$(BLUE)[TEST]$(RESET) 运行测试（被动代理模式）..."
	@go test -tags $(PASSIVE_TAG) -v ./...

.PHONY: test-both
test-both: test test-passive ## 运行测试（主动+被动）

.PHONY: test-race
test-race: ## 运行竞态检测测试（主动模式）
	@echo "$(BLUE)[TEST-RACE]$(RESET) 运行竞态检测测试（主动模式）..."
	@go test -race -v ./...

.PHONY: test-race-passive
test-race-passive: ## 运行竞态检测测试（被动代理模式，-tags passive）
	@echo "$(BLUE)[TEST-RACE]$(RESET) 运行竞态检测测试（被动代理模式）..."
	@go test -tags $(PASSIVE_TAG) -race -v ./...

.PHONY: test-race-both
test-race-both: test-race test-race-passive ## 运行竞态检测测试（主动+被动）

.PHONY: bench
bench: ## 运行性能测试
	@echo "$(BLUE)[BENCH]$(RESET) 运行性能测试..."
	@go test -bench=. -benchmem ./...

.PHONY: coverage
coverage: ## 生成测试覆盖率报告
	@echo "$(BLUE)[COVERAGE]$(RESET) 生成测试覆盖率报告..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)[SUCCESS]$(RESET) 覆盖率报告: coverage.html"

# ============================================================================
# 发布命令
# ============================================================================

.PHONY: release
release: build-all ## 创建发布包（主动模式）
	@echo "$(BLUE)[RELEASE]$(RESET) 创建发布包（主动模式）..."
	@VERSION=$(VERSION) ./release.sh

.PHONY: release-passive
release-passive: build-all-passive ## 创建发布包（被动代理模式）
	@echo "$(BLUE)[RELEASE]$(RESET) 创建发布包（被动代理模式）..."
	@mkdir -p $(PASSIVE_RELEASE_DIR)
	@VERSION=$(VERSION) ./release.sh -b $(PASSIVE_BUILD_DIR) -r $(PASSIVE_RELEASE_DIR)

.PHONY: release-both
release-both: release release-passive ## 创建发布包（主动+被动）

.PHONY: release-clean
release-clean: clean-release build-all ## 清理并创建发布包（主动模式）
	@echo "$(BLUE)[RELEASE-CLEAN]$(RESET) 清理并创建发布包（主动模式）..."
	@VERSION=$(VERSION) ./release.sh

.PHONY: release-clean-passive
release-clean-passive: clean-release build-all-passive ## 清理并创建发布包（被动代理模式）
	@echo "$(BLUE)[RELEASE-CLEAN]$(RESET) 清理并创建发布包（被动代理模式）..."
	@mkdir -p $(PASSIVE_RELEASE_DIR)
	@VERSION=$(VERSION) ./release.sh -b $(PASSIVE_BUILD_DIR) -r $(PASSIVE_RELEASE_DIR)

.PHONY: release-clean-both
release-clean-both: release-clean release-clean-passive ## 清理并创建发布包（主动+被动）

# ============================================================================
# 开发命令
# ============================================================================

.PHONY: dev
dev: build ## 开发模式 (编译并运行)
	@echo "$(BLUE)[DEV]$(RESET) 开发模式..."
	@$(BUILD_DIR)/$(PROJECT_NAME) --help

.PHONY: install
install: build ## 安装到系统
	@echo "$(BLUE)[INSTALL]$(RESET) 安装到系统..."
	@sudo cp $(BUILD_DIR)/$(PROJECT_NAME) /usr/local/bin/
	@echo "$(GREEN)[SUCCESS]$(RESET) 安装完成: /usr/local/bin/$(PROJECT_NAME)"

.PHONY: uninstall
uninstall: ## 从系统卸载
	@echo "$(BLUE)[UNINSTALL]$(RESET) 从系统卸载..."
	@sudo rm -f /usr/local/bin/$(PROJECT_NAME)
	@echo "$(GREEN)[SUCCESS]$(RESET) 卸载完成"

# ============================================================================
# 质量检查
# ============================================================================

.PHONY: lint
lint: ## 代码检查
	@echo "$(BLUE)[LINT]$(RESET) 代码检查..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)[WARNING]$(RESET) golangci-lint 未安装，使用 go vet"; \
		go vet ./...; \
	fi

.PHONY: fmt
fmt: ## 格式化代码
	@echo "$(BLUE)[FMT]$(RESET) 格式化代码..."
	@go fmt ./...
	@echo "$(GREEN)[SUCCESS]$(RESET) 代码格式化完成"

.PHONY: mod-update
mod-update: ## 更新依赖包
	@echo "$(BLUE)[MOD-UPDATE]$(RESET) 更新依赖包..."
	@go get -u ./...
	@go mod tidy
	@echo "$(GREEN)[SUCCESS]$(RESET) 依赖包更新完成"

# ============================================================================
# 信息命令
# ============================================================================

.PHONY: info
info: ## 显示构建信息
	@echo "$(BLUE)构建信息$(RESET)"
	@echo "=================================="
	@echo "项目名称:     $(PROJECT_NAME)"
	@echo "版本:         $(VERSION)"
	@echo "Go版本:       $(GO_VERSION)"
	@echo "Git提交:      $(GIT_COMMIT)"
	@echo "Git分支:      $(GIT_BRANCH)"
	@echo "构建时间:     $(BUILD_TIME)"
	@echo "构建目录:     $(BUILD_DIR)"
	@echo "发布目录:     $(RELEASE_DIR)"
	@echo ""
	@echo "$(BLUE)支持平台$(RESET)"
	@echo "=================================="
	@for platform in $(PLATFORMS); do echo "  $$platform"; done

.PHONY: size
size: ## 显示二进制文件大小
	@echo "$(BLUE)[SIZE]$(RESET) 二进制文件大小:"
	@if [ -d "$(BUILD_DIR)" ]; then \
		ls -lh $(BUILD_DIR)/ | tail -n +2 | awk '{print "  " $$9 ": " $$5}'; \
	else \
		echo "  $(YELLOW)[WARNING]$(RESET) 构建目录不存在，请先运行 make build"; \
	fi

# ============================================================================
# 特殊目标
# ============================================================================

.PHONY: docker-build
docker-build: ## Docker 构建
	@echo "$(BLUE)[DOCKER]$(RESET) Docker 构建..."
	@docker build -t $(PROJECT_NAME):$(VERSION) .
	@echo "$(GREEN)[SUCCESS]$(RESET) Docker 镜像构建完成"

.PHONY: quick
quick: clean-dist build ## 快速构建 (清理+编译)
	@echo "$(GREEN)[SUCCESS]$(RESET) 快速构建完成"

.PHONY: all
all: clean deps check test build-all compress ## 完整构建流程（主动模式）
	@echo "$(GREEN)[SUCCESS]$(RESET) 完整构建流程完成"

.PHONY: all-both
all-both: clean deps check test-both build-all-both compress ## 完整构建流程（主动+被动）
	@echo "$(GREEN)[SUCCESS]$(RESET) 完整构建流程完成（主动+被动）"

# ============================================================================
# 文件目标
# ============================================================================

# 防止文件名冲突
.PHONY: build build-passive build-both build-all build-all-passive build-all-both \
        build-windows build-windows-passive build-windows-both \
        build-linux build-linux-passive build-linux-both \
        build-darwin build-darwin-passive build-darwin-both \
        build-optimized build-optimized-passive build-optimized-both \
        build-debug build-debug-passive build-debug-both \
        compress clean clean-dist clean-release \
        deps verify check test test-passive test-both test-race test-race-passive test-race-both bench coverage \
        release release-passive release-both release-clean release-clean-passive release-clean-both \
        dev install uninstall lint fmt mod-update info size docker-build \
        quick all all-both help 

.PHONY: build-darwin-optimized build-darwin-debug test-macos-optimization 

# macOS专用优化构建
build-darwin-optimized: ## 编译macOS优化版本
	@echo "[BUILD-DARWIN-OPTIMIZED] 编译macOS优化版本..."
	@$(BUILD_SCRIPT) darwin/amd64 --with-macos-optimization
	@$(BUILD_SCRIPT) darwin/arm64 --with-macos-optimization

# macOS调试版本
build-darwin-debug: deps ## 编译macOS调试版本 (保留调试信息)
	@echo "[BUILD-DARWIN-DEBUG] 编译macOS调试版本..."
	@mkdir -p $(OUTPUT_DIR)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_amd64_debug $(MAIN_FILE)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_arm64_debug $(MAIN_FILE)

# 测试macOS优化效果
test-macos-optimization: clean build-darwin-debug build-darwin-optimized ## 对比macOS优化效果
	@echo "[TEST-MACOS] 对比macOS优化效果..."
	@echo "=========================================="
	@echo "🍎 macOS二进制文件大小对比:"
	@echo "=========================================="
	@if [ -f "$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_amd64_debug" ]; then \
		DEBUG_SIZE=$$($(call get_file_size,$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_amd64_debug)); \
		echo "  调试版本 (amd64): $$DEBUG_SIZE"; \
	fi
	@if [ -f "$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_amd64" ]; then \
		OPT_SIZE=$$($(call get_file_size,$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_amd64)); \
		echo "  优化版本 (amd64): $$OPT_SIZE"; \
	fi
	@if [ -f "$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_arm64_debug" ]; then \
		DEBUG_SIZE=$$($(call get_file_size,$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_arm64_debug)); \
		echo "  调试版本 (arm64): $$DEBUG_SIZE"; \
	fi
	@if [ -f "$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_arm64" ]; then \
		OPT_SIZE=$$($(call get_file_size,$(OUTPUT_DIR)/$(PROJECT_NAME)_darwin_arm64)); \
		echo "  优化版本 (arm64): $$OPT_SIZE"; \
	fi
	@echo "=========================================="
