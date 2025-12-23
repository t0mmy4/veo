package checkalive

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"veo/internal/core/config"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
)

// ConnectivityChecker 连通性检测器
type ConnectivityChecker struct {
	client *httpclient.Client
	config *config.Config
}

// NewConnectivityChecker 创建连通性检测器
func NewConnectivityChecker(cfg *config.Config) *ConnectivityChecker {
	// 构造HTTP客户端配置
	httpCfg := httpclient.DefaultConfig()

	// 从全局配置覆盖超时时间
	if cfg != nil && cfg.Addon.Request.Timeout > 0 {
		httpCfg.Timeout = time.Duration(cfg.Addon.Request.Timeout) * time.Second
	} else {
		httpCfg.Timeout = 5 * time.Second // 默认5秒，快速失败
	}

	// 禁用重定向以加快检测速度
	httpCfg.FollowRedirect = false
	// 即使证书无效也认为是存活的
	httpCfg.SkipTLSVerify = true

	return &ConnectivityChecker{
		client: httpclient.New(httpCfg),
		config: cfg,
	}
}

// BatchCheck 批量检测目标连通性
func (cc *ConnectivityChecker) BatchCheck(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}

	logger.Debugf("开始目标连通性检测，目标数量: %d", len(targets))

	// 标准化所有目标
	parser := NewTargetParser()
	var candidates []string
	for _, t := range targets {
		normalized := parser.NormalizeURL(t)
		candidates = append(candidates, normalized...)
	}

	var validTargets []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制并发数
	concurrency := 20
	if cc.config != nil && cc.config.Module.Dirscan {
		concurrency = 50
	}
	sem := make(chan struct{}, concurrency)

	var processedCount int64
	total := len(candidates)

	logger.Info("开始检测目标存活性...")

	for _, url := range candidates {
		wg.Add(1)

		go func(targetURL string) {
			sem <- struct{}{}
			defer func() {
				<-sem
				wg.Done()
			}()

			if cc.isReachable(targetURL) {
				mu.Lock()
				validTargets = append(validTargets, targetURL)
				mu.Unlock()
			}

			current := atomic.AddInt64(&processedCount, 1)
			if total > 0 && (current%5 == 0 || current == int64(total)) {
				fmt.Printf("\r存活性检测: %d/%d (%.1f%%)", current, total, float64(current)/float64(total)*100)
			}
		}(url)
	}

	wg.Wait()
	fmt.Println() // Newline after progress

	logger.Debugf("有效目标: %d/%d", len(validTargets), len(candidates))
	return validTargets
}

// isReachable 检测单个URL是否可连通
func (cc *ConnectivityChecker) isReachable(urlStr string) bool {
	// 尝试发送请求
	// 注意：httpclient.MakeRequest 默认是 GET。对于存活检测，GET 是最可靠的。
	_, statusCode, err := cc.client.MakeRequest(urlStr)
	if err != nil {
		logger.Debugf("目标不可连通: %s (%v)", urlStr, err)
		return false
	}
	// 只要有响应（无论状态码如何，只要不是网络错误），都认为存活
	logger.Debugf("目标可连通: %s [%d]", urlStr, statusCode)
	return true
}

// ValidateAndNormalize 验证并标准化目标列表 (不进行网络检测)
func (cc *ConnectivityChecker) ValidateAndNormalize(targets []string) ([]string, error) {
	logger.Debugf("开始验证和标准化目标列表")

	var validTargets []string
	parser := NewTargetParser()

	for _, target := range targets {
		// 验证URL格式
		if err := parser.ValidateURL(target); err != nil {
			logger.Warnf("跳过无效目标 %s: %v", target, err)
			continue
		}

		// 标准化URL
		urls := parser.NormalizeURL(target)
		if len(urls) > 0 {
			// 如果不进行网络检测，只取第一个标准化的URL
			validTargets = append(validTargets, urls[0])
		}
	}

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	return validTargets, nil
}
