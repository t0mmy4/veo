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
	httpCfg := httpclient.DefaultConfig()

	if cfg != nil && cfg.Addon.Request.Timeout > 0 {
		httpCfg.Timeout = time.Duration(cfg.Addon.Request.Timeout) * time.Second
	} else {
		httpCfg.Timeout = 5 * time.Second
	}

	httpCfg.FollowRedirect = false
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

	parser := NewTargetParser()
	var candidates []string
	for _, t := range targets {
		normalized := parser.NormalizeURL(t)
		candidates = append(candidates, normalized...)
	}

	var validTargets []string
	var mu sync.Mutex
	var wg sync.WaitGroup

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
	fmt.Println()

	logger.Debugf("有效目标: %d/%d", len(validTargets), len(candidates))
	if len(validTargets) > 0 {
		logger.Debug("存活目标列表:")
		for _, target := range validTargets {
			logger.Debugf("  %s", target)
		}
	}
	return validTargets
}

func (cc *ConnectivityChecker) isReachable(urlStr string) bool {
	_, statusCode, err := cc.client.MakeRequest(urlStr)
	if err != nil {
		logger.Debugf("目标不可连通: %s (%v)", urlStr, err)
		return false
	}
	logger.Debugf("目标可连通: %s [%d]", urlStr, statusCode)
	return true
}

// ValidateAndNormalize 验证并标准化目标列表 (不进行网络检测)
func (cc *ConnectivityChecker) ValidateAndNormalize(targets []string) ([]string, error) {
	logger.Debugf("开始验证和标准化目标列表")

	var validTargets []string
	parser := NewTargetParser()

	for _, target := range targets {
		if err := parser.ValidateURL(target); err != nil {
			logger.Warnf("跳过无效目标 %s: %v", target, err)
			continue
		}

		urls := parser.NormalizeURL(target)
		if len(urls) > 0 {
			validTargets = append(validTargets, urls[0])
		}
	}

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	return validTargets, nil
}
