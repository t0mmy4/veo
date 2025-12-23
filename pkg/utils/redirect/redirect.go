package redirect

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

var (
	// Simplified Regex for redirects
	metaRefreshRe    = regexp.MustCompile(`(?is)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`)
	metaRefreshRe2   = regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)['"][^>]*http-equiv\s*=\s*['"]?refresh['"]?`)
	jsLocationRe     = regexp.MustCompile(`(?is)(?:window\.|self\.|top\.|parent\.|document\.|location\s*=)\s*location(?:.href)?\s*=\s*['"]([^'"]+)['"]`)
	jsLocationFuncRe = regexp.MustCompile(`(?is)(?:window\.|self\.|top\.|parent\.|document\.|location\s*\.)location\.(?:replace|assign)\(\s*['"]([^'"]+)['"]\s*\)`)
)

// HTTPFetcher 定义最小化HTTP客户端接口
type HTTPFetcher interface {
	MakeRequest(rawURL string) (body string, statusCode int, err error)
}

// HTTPFetcherFull 扩展的HTTP客户端接口
type HTTPFetcherFull interface {
	MakeRequestFull(rawURL string) (body string, statusCode int, headers map[string][]string, err error)
}

// Config 跳转跟随配置
type Config struct {
	MaxRedirects   int  // 最大跳转次数
	FollowRedirect bool // 是否跟随跳转
	SameHostOnly   bool // 是否限制同域名/子域名跳转
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		MaxRedirects:   5,
		FollowRedirect: true,
		SameHostOnly:   true,
	}
}

// IsRedirectStatus checks if the status code indicates a redirect.
func IsRedirectStatus(code int) bool {
	return code >= 301 && code <= 308 && code != 304 && code != 305 && code != 306
}

// GetHeaderFirst safely retrieves the first value for a header key.
func GetHeaderFirst(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	lowerKey := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == lowerKey && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// Execute 执行请求并处理跳转逻辑
func Execute(rawURL string, fetcher HTTPFetcherFull, config *Config) (*interfaces.HTTPResponse, error) {
	if config == nil {
		config = DefaultConfig()
	}

	currentURL := rawURL
	var response *interfaces.HTTPResponse
	var redirectCount int

	for {
		body, statusCode, headers, err := fetcher.MakeRequestFull(currentURL)
		if err != nil {
			return nil, err
		}

		response = &interfaces.HTTPResponse{
			URL:             currentURL,
			Method:          "GET",
			StatusCode:      statusCode,
			Body:            body,
			ResponseBody:    body,
			ResponseHeaders: headers,
			ContentLength:   int64(len(body)),
			Length:          int64(len(body)),
			IsDirectory:     strings.HasSuffix(currentURL, "/"),
			ContentType:     GetHeaderFirst(headers, "Content-Type"),
		}

		titleExtractor := shared.NewTitleExtractor()
		response.Title = titleExtractor.ExtractTitle(body)

		if !config.FollowRedirect {
			return response, nil
		}

		if redirectCount >= config.MaxRedirects {
			logger.Warnf("超过最大重定向次数(%d): %s", config.MaxRedirects, currentURL)
			return response, nil
		}

		var nextURL string
		isRedirect := false

		// HTTP 3xx
		if IsRedirectStatus(statusCode) {
			loc := GetHeaderFirst(headers, "Location")
			if loc != "" {
				nextURL = ResolveRedirectURL(currentURL, loc)
				if nextURL != "" {
					isRedirect = true
					logger.Debugf("捕获HTTP重定向 %d: %s -> %s", statusCode, currentURL, nextURL)
				}
			}
		}

		// Client Meta/JS
		if !isRedirect && statusCode >= 200 {
			redirectLink := DetectClientRedirectURL(body)
			if redirectLink != "" {
				resolvedURL := ResolveRedirectURL(currentURL, redirectLink)
				if resolvedURL != "" {
					nextURL = resolvedURL
					isRedirect = true
					logger.Debugf("捕获客户端重定向: %s -> %s", currentURL, nextURL)
				}
			}
		}

		if !isRedirect {
			return response, nil
		}

		if config.SameHostOnly && !ShouldFollowRedirect(currentURL, nextURL) {
			logger.Debugf("放弃跨主机重定向: %s -> %s", currentURL, nextURL)
			return response, nil
		}

		redirectCount++
		currentURL = nextURL
	}
}

// FollowClientRedirect 检测并跟随客户端（HTML/JS）重定向
func FollowClientRedirect(response *interfaces.HTTPResponse, fetcher HTTPFetcher) (*interfaces.HTTPResponse, error) {
	if response == nil || fetcher == nil {
		return nil, nil
	}

	redirectBody := response.ResponseBody
	if redirectBody == "" {
		redirectBody = response.Body
	}
	if strings.TrimSpace(redirectBody) == "" {
		return nil, nil
	}

	redirectURL := DetectClientRedirectURL(redirectBody)
	if redirectURL == "" {
		return nil, nil
	}

	absoluteURL := ResolveRedirectURL(response.URL, redirectURL)
	if absoluteURL == "" {
		return nil, fmt.Errorf("无法解析客户端重定向URL: %s", redirectURL)
	}

	var body string
	var statusCode int
	var headers map[string][]string
	var err error

	if fullFetcher, ok := fetcher.(HTTPFetcherFull); ok {
		body, statusCode, headers, err = fullFetcher.MakeRequestFull(absoluteURL)
	} else {
		body, statusCode, err = fetcher.MakeRequest(absoluteURL)
	}

	if err != nil {
		return nil, fmt.Errorf("跟随客户端重定向失败: %w", err)
	}

	titleExtractor := shared.NewTitleExtractor()
	title := titleExtractor.ExtractTitle(body)

	return &interfaces.HTTPResponse{
		URL:             absoluteURL,
		Method:          "GET",
		StatusCode:      statusCode,
		Body:            body,
		ResponseBody:    body,
		ContentType:     GetHeaderFirst(headers, "Content-Type"),
		ContentLength:   int64(len(body)),
		Length:          int64(len(body)),
		Title:           title,
		ResponseHeaders: headers,
		IsDirectory:     strings.HasSuffix(absoluteURL, "/"),
	}, nil
}

// DetectClientRedirectURL 检测HTML/JS中的客户端重定向URL
func DetectClientRedirectURL(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}

	// Meta Refresh
	if m := metaRefreshRe.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	if m := metaRefreshRe2.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	// JS Location
	if m := jsLocationRe.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	if m := jsLocationFuncRe.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	return ""
}

// ResolveRedirectURL 将相对/协议相对URL解析为绝对地址
func ResolveRedirectURL(baseRaw, ref string) string {
	ref = strings.TrimSpace(ref)
	if baseRaw == "" || ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	base, err := url.Parse(baseRaw)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(ref, "//") {
		ref = base.Scheme + ":" + ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

// ShouldFollowRedirect 判断是否应该跟随重定向（同主机/域名检查）
func ShouldFollowRedirect(currentURL, nextURL string) bool {
	u1, err := url.Parse(currentURL)
	if err != nil {
		return false
	}
	u2, err := url.Parse(nextURL)
	if err != nil {
		return false
	}

	h1 := strings.ToLower(u1.Hostname())
	h2 := strings.ToLower(u2.Hostname())

	if h1 == h2 {
		return true
	}
	if strings.HasSuffix(h2, "."+h1) || strings.HasSuffix(h1, "."+h2) {
		return true
	}
	return false
}
