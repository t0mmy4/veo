package main

import (
	"veo/internal/cli"
)

// 版本信息：由构建系统通过 -ldflags "-X main.<name>=..." 注入
// 注意：变量名需与 Makefile/build.sh 中的 -X 保持一致
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
	gitBranch = "unknown"
)

func main() {
	// 执行CLI命令
	cli.Execute()
}
