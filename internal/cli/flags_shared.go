package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	modulepkg "veo/pkg/core/module"
	fpaddon "veo/pkg/fingerprint"
	"veo/pkg/utils/logger"
)

type arrayFlags []string

func (af *arrayFlags) String() string {
	return strings.Join(*af, ", ")
}

func (af *arrayFlags) Set(value string) error {
	*af = append(*af, value)
	return nil
}

// ValidModules 有效的模块列表（使用module包的类型定义）
var ValidModules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan)}

// HasModule 检查是否包含指定模块
func (args *CLIArgs) HasModule(module string) bool {
	for _, m := range args.Modules {
		if m == module {
			return true
		}
	}
	return false
}

// getMaxInt 获取两个整数中的最大值，用于处理短参数和长参数
func getMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getStringValue 获取字符串参数值，优先使用非空值，用于处理短参数和长参数
func getStringValue(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseCommaSeparatedString 解析逗号分隔的字符串
func parseCommaSeparatedString(input string) []string {
	if input == "" {
		return []string{}
	}

	items := strings.Split(input, ",")
	var cleanItems []string

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleanItems = append(cleanItems, item)
		}
	}
	return cleanItems
}

func parseTargets(targetsStr string) []string {
	return parseCommaSeparatedString(targetsStr)
}

func parseModules(modulesStr string) []string {
	return parseCommaSeparatedString(modulesStr)
}

// validateWordlistFile 验证字典文件
func validateWordlistFile(wordlistPath string) error {
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return fmt.Errorf("字典文件不存在: %s", wordlistPath)
	}

	// 检查文件是否可读
	file, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("无法读取字典文件: %v", err)
	}
	file.Close()

	return nil
}

// validateOutputPath 验证输出路径
func validateOutputPath(outputPath string) error {
	// 统一输出为 <base>_realtime.csv，outputPath 仅作为前缀使用（允许任意后缀/无后缀）
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return fmt.Errorf("输出路径不能为空")
	}

	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	realtimePath := base + "_realtime.csv"

	// 获取目录路径
	dir := filepath.Dir(realtimePath)

	// 如果目录不存在，尝试创建
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("无法创建输出目录 %s: %v", dir, err)
		}
	}

	// 检查目录是否可写
	testFile := filepath.Join(dir, ".veo_write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("输出目录不可写 %s: %v", dir, err)
	}
	os.Remove(testFile) // 清理测试文件

	return nil
}

func validateModules(modules []string) error {
	for _, module := range modules {
		if !isValidModule(module) {
			return fmt.Errorf("无效的模块: '%s'，支持的模块: %s", module, strings.Join(ValidModules, ", "))
		}
	}
	return nil
}

// isValidModule 检查模块是否有效
func isValidModule(module string) bool {
	for _, validModule := range ValidModules {
		if module == validModule {
			return true
		}
	}
	return false
}

func parseHeaderFlags(headers []string) (map[string]string, error) {
	parsed := make(map[string]string)
	for _, header := range headers {
		h := strings.TrimSpace(header)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\r\n") {
			return nil, fmt.Errorf("头部不能包含换行符: %q", h)
		}
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的头部格式: %s (需要 Header: Value)", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("头部名称不能为空: %s", h)
		}
		if value == "" {
			return nil, fmt.Errorf("头部值不能为空: %s", h)
		}
		parsed[key] = value
	}
	return parsed, nil
}

// parseStatusCodes 解析CLI参数中的状态码字符串
func parseStatusCodes(statusCodesStr string) ([]int, error) {
	if statusCodesStr == "" {
		return nil, fmt.Errorf("状态码字符串不能为空")
	}

	// 分割逗号分隔的状态码
	codeStrings := strings.Split(statusCodesStr, ",")
	statusCodes := make([]int, 0, len(codeStrings))

	for _, codeStr := range codeStrings {
		codeStr = strings.TrimSpace(codeStr)
		if codeStr == "" {
			continue // 跳过空字符串
		}

		// 转换为整数
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			return nil, fmt.Errorf("无效的状态码 '%s': 必须是整数", codeStr)
		}

		// 验证状态码范围
		if err := validateStatusCode(code); err != nil {
			return nil, fmt.Errorf("无效的状态码 %d: %v", code, err)
		}

		statusCodes = append(statusCodes, code)
		logger.Debugf("解析状态码: %d", code)
	}

	if len(statusCodes) == 0 {
		return nil, fmt.Errorf("未解析到有效的状态码")
	}

	return statusCodes, nil
}

// validateStatusCode 验证单个状态码的有效性
func validateStatusCode(code int) error {
	// HTTP状态码范围: 100-599
	if code < 100 || code > 599 {
		return fmt.Errorf("状态码必须在100-599之间")
	}
	return nil
}

func parseWordlistPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func buildHostAllowList(targets []string) []string {
	allow := make([]string, 0, len(targets)*2)
	seen := make(map[string]struct{})
	for _, raw := range targets {
		host, port, wildcard := normalizeTargetHost(raw)
		if host == "" {
			continue
		}
		add := func(value string) {
			value = strings.TrimSpace(strings.ToLower(value))
			if value == "" {
				return
			}
			if _, ok := seen[value]; ok {
				return
			}
			allow = append(allow, value)
			seen[value] = struct{}{}
		}
		add(host)
		if port != "" {
			add(host + ":" + port)
		}
		if wildcard {
			continue
		}
	}
	return allow
}

func normalizeTargetHost(raw string) (host string, port string, wildcard bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	candidate := s
	if strings.Contains(s, "://") {
		if parsed, err := url.Parse(s); err == nil {
			candidate = parsed.Host
		}
	}
	if idx := strings.Index(candidate, "/"); idx != -1 {
		candidate = candidate[:idx]
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", "", false
	}
	if at := strings.LastIndex(candidate, "@"); at != -1 {
		candidate = candidate[at+1:]
	}
	port = ""
	hostPart := candidate
	if strings.HasPrefix(hostPart, "[") {
		if h, p, err := net.SplitHostPort(hostPart); err == nil {
			hostPart, port = h, p
		} else {
			hostPart = strings.Trim(hostPart, "[]")
		}
	} else {
		if h, p, err := net.SplitHostPort(hostPart); err == nil {
			hostPart, port = h, p
		}
	}
	hostPart = strings.TrimSpace(hostPart)
	if hostPart == "" {
		return "", "", false
	}
	lower := strings.ToLower(hostPart)
	return lower, port, strings.HasPrefix(lower, "*.")
}

// handleRuleUpdates 处理指纹库更新逻辑
func handleRuleUpdates(args *CLIArgs) {
	updater := fpaddon.NewUpdater("config/fingerprint/finger.yaml")

	if args.UpdateRules {
		logger.Info("正在检查并更新指纹识别规则库...")
		if err := updater.UpdateRules(); err != nil {
			logger.Fatalf("指纹库更新失败: %v", err)
		}
		logger.Info("指纹库更新完成")
		os.Exit(0)
	}

	// 检查更新 (同步执行，确保在扫描前提示)
	// 使用短超时 (1s) 避免阻塞过久
	hasUpdate, localVer, remoteVer, err := updater.CheckForUpdates()
	if err != nil {
		logger.Debugf("检查指纹库更新失败: %v", err)
		return
	}

	if hasUpdate {
		msg := fmt.Sprintf("发现新的指纹库版本: %s (当前: %s)，请运行 --update-rules 进行更新", remoteVer, localVer)
		logger.Info(msg)
	} else {
		logger.Debugf("指纹库已是最新版本: %s", localVer)
	}
}
