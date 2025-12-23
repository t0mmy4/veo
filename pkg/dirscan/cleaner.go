package dirscan

import (
	"net/url"
	"regexp"
	"strings"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

// URLCleaner 负责URL的清理、规范化和参数过滤
type URLCleaner struct {
	staticExtensions  []string
	staticPaths       []string
	invalidParams     map[string]bool
	authParams        map[string]bool
	timestampPatterns []string
}

// NewURLCleaner 创建新的URL清理器
func NewURLCleaner() *URLCleaner {
	c := &URLCleaner{
		// 默认配置
		invalidParams: map[string]bool{
			"_t": true, "time": true, "timestamp": true, "_": true,
			"cachebust": true, "nocache": true, "v": true, "version": true,
			"rand": true, "random": true, "_random": true, "cb": true, "callback": true,
		},
		authParams: map[string]bool{
			"token": true, "auth": true, "authorization": true, "bearer": true,
			"jwt": true, "access_token": true, "refresh_token": true,
			"api_key": true, "apikey": true, "secret": true,
			"session": true, "sessionid": true, "sid": true,
			"jsessionid": true, "phpsessid": true,
			"userid": true, "user_id": true, "uid": true, "username": true,
			"account": true, "email": true, "role": true, "group": true,
			"tenant": true, "tenant_id": true,
			"permission": true, "scope": true, "access": true, "privilege": true,
		},
		timestampPatterns: []string{
			`^\d{10}$`, `^\d{13}$`, `^\d{16}$`, `^[0-9]{8,}$`,
		},
	}
	return c
}

// SetStaticExtensions 设置静态文件扩展名
func (c *URLCleaner) SetStaticExtensions(exts []string) {
	c.staticExtensions = exts
}

// SetStaticPaths 设置静态路径
func (c *URLCleaner) SetStaticPaths(paths []string) {
	c.staticPaths = paths
}

// IsStaticResource 检查URL是否为静态资源
func (c *URLCleaner) IsStaticResource(rawURL string) bool {
	lowerURL := strings.ToLower(rawURL)

	// 检查是否包含静态目录
	for _, dir := range c.staticPaths {
		if strings.Contains(lowerURL, strings.ToLower(dir)) {
			logger.Debugf("匹配静态目录，过滤: %s", rawURL)
			return true
		}
	}

	// 检查是否以静态文件扩展名结尾
	checker := shared.NewFileExtensionChecker()
	// 如果设置了自定义扩展名，可能需要合并逻辑，但目前shared.Checker涵盖了通用的
	// 这里假设 shared.Checker 是基础，c.staticExtensions 是额外的？
	// 原代码逻辑：isStatic := c.hasStaticExtension(...)
	// 原代码直接调用 shared.NewFileExtensionChecker().IsStaticFile(lowerURL)
	// 并没有使用 c.staticExtensions ！！！ 这是一个BUG或者原代码的无用字段。
	// 原代码：
	// func (c *Collector) hasStaticExtension(lowerURL string, extensions []string) bool {
	//    checker := shared.NewFileExtensionChecker()
	//    return checker.IsStaticFile(lowerURL)
	// }
	// extensions 参数被忽略了。

	if checker.IsStaticFile(lowerURL) {
		logger.Debugf("匹配静态扩展名，过滤: %s", rawURL)
		return true
	}

	// 如果我们要支持自定义扩展名：
	for _, ext := range c.staticExtensions {
		if strings.HasSuffix(lowerURL, strings.ToLower(ext)) {
			return true
		}
	}

	return false
}

// CleanURLParams 清理URL参数
func (c *URLCleaner) CleanURLParams(rawURL string) string {
	// 1. 验证和修复URL
	valid, fixedURL := c.validateAndFixURL(rawURL)
	if !valid {
		return ""
	}

	parsedURL, err := url.Parse(fixedURL)
	if err != nil {
		return ""
	}

	// 2. 清理路径ID
	pathCleaned := c.cleanPathID(parsedURL)

	// 3. 过滤查询参数
	if parsedURL.RawQuery == "" && !pathCleaned {
		return fixedURL
	}

	validParams := url.Values{}
	for key, values := range parsedURL.Query() {
		if c.isValidParam(key, values) {
			validParams[key] = values
		}
	}

	if len(validParams) == 0 {
		parsedURL.RawQuery = ""
	} else {
		parsedURL.RawQuery = validParams.Encode()
	}

	return parsedURL.String()
}

// validateAndFixURL 验证并尝试修复URL
func (c *URLCleaner) validateAndFixURL(rawURL string) (bool, string) {
	if rawURL == "" {
		return false, ""
	}

	fixedURL := rawURL
	// 修复协议相对URL
	if strings.HasPrefix(rawURL, "//") {
		hostAndPath := rawURL[2:]
		if hostAndPath == "" {
			return false, ""
		}

		// 简单启发式：有443端口则https，否则http
		if strings.Contains(hostAndPath, ":443") {
			// 移除 :443 并加 https
			hostAndPath = strings.Replace(hostAndPath, ":443", "", 1)
			fixedURL = "https://" + hostAndPath
		} else {
			fixedURL = "http://" + hostAndPath
		}
	}

	// 检查协议
	lower := strings.ToLower(fixedURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false, ""
	}

	return true, fixedURL
}

func (c *URLCleaner) cleanPathID(u *url.URL) bool {
	path := strings.TrimRight(u.Path, "/")
	idx := strings.LastIndex(path, "/")
	if idx == -1 {
		return false
	}

	segment := path[idx+1:]
	// 检查是否纯数字
	isNumeric := true
	if segment == "" {
		isNumeric = false
	}
	for _, r := range segment {
		if r < '0' || r > '9' {
			isNumeric = false
			break
		}
	}

	if isNumeric {
		u.Path = path[:idx]
		return true
	}
	return false
}

func (c *URLCleaner) isValidParam(key string, values []string) bool {
	lowerKey := strings.ToLower(key)
	if c.invalidParams[lowerKey] {
		return false
	}
	if c.authParams[lowerKey] {
		return true
	}

	// 检查值是否像时间戳
	for _, v := range values {
		for _, p := range c.timestampPatterns {
			if matched, _ := regexp.MatchString(p, v); matched {
				return false
			}
		}
	}
	return true
}
