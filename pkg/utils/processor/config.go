package processor

import (
	"time"

	"veo/pkg/utils/useragent"
)

// RequestConfig 请求配置
type RequestConfig struct {
	Timeout            time.Duration
	MaxRetries         int
	UserAgents         []string
	MaxBodySize        int
	FollowRedirect     bool
	MaxRedirects       int
	MaxConcurrent      int
	ConnectTimeout     time.Duration
	KeepAlive          time.Duration
	RandomUserAgent    bool
	Delay              time.Duration
	ProxyURL           string
	DecompressResponse bool
}

const DefaultMaxRedirects = 3

// ApplyRedirectPolicy 统一重定向策略（指纹识别/目录扫描共用）
func ApplyRedirectPolicy(config *RequestConfig) {
	if config == nil {
		return
	}
	config.FollowRedirect = true
	config.MaxRedirects = DefaultMaxRedirects
}

// GetDefaultConfig 暴露默认配置获取方法（测试用）
func GetDefaultConfig() *RequestConfig {
	return getDefaultConfig()
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *RequestConfig {
	timeout := 10 * time.Second
	retries := 3
	maxConcurrent := 100
	connectTimeout := 5 * time.Second
	maxRedirects := DefaultMaxRedirects

	randomUserAgent := false

	delay := time.Duration(0)

	userAgents := useragent.GetEffectiveList()
	if len(userAgents) == 0 {
		userAgents = useragent.DefaultList()
	}

	return &RequestConfig{
		Timeout:            timeout,
		MaxRetries:         retries,
		UserAgents:         userAgents,
		MaxBodySize:        10 * 1024 * 1024,
		FollowRedirect:     false,
		MaxRedirects:       maxRedirects,
		MaxConcurrent:      maxConcurrent,
		ConnectTimeout:     connectTimeout,
		RandomUserAgent:    randomUserAgent,
		Delay:              delay,
		DecompressResponse: true,
	}
}

func initializeUserAgentPool(config *RequestConfig) []string {
	effective := useragent.GetEffectiveList()
	if len(effective) == 0 {
		return effective
	}

	if config != nil && !config.RandomUserAgent {
		return []string{effective[0]}
	}

	return effective
}
