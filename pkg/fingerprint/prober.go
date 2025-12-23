package fingerprint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

// TriggerActiveProbing 触发主动探测（异步，用于被动模式）
func (e *Engine) TriggerActiveProbing(baseURL string, httpClient httpclient.HTTPClientInterface, timeout time.Duration) {
	if httpClient == nil {
		return
	}
	go func() {
		// 使用配置的超时
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		// 执行主动Path探测
		_, _ = e.ExecuteActiveProbing(ctx, baseURL, httpClient)

		// 执行404探测
		_, _ = e.Execute404Probing(ctx, baseURL, httpClient)
	}()
}

// ExecuteActiveProbing 执行主动指纹探测（同步返回结果）
func (e *Engine) ExecuteActiveProbing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) ([]*ProbeResult, error) {
	logger.Debugf("开始主动探测: %s", baseURL)

	// 获取所有包含path字段的规则和header规则
	pathRules := e.ruleManager.GetPathRules()
	headerOnlyRules := e.ruleManager.GetHeaderRules()
	totalPaths := e.ruleManager.GetPathRulesCount()

	if totalPaths == 0 && len(headerOnlyRules) == 0 {
		logger.Debug("没有需要主动探测的规则，跳过主动探测")
		return nil, nil
	}

	// 验证baseURL格式
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("URL解析失败: %v", err)
	}

	var results []*ProbeResult
	var resultsMu sync.Mutex

	// 任务列表
	type task struct {
		rule *FingerprintRule
		path string
	}
	var tasks []task

	for _, rule := range pathRules {
		for _, p := range rule.Paths {
			tasks = append(tasks, task{rule: rule, path: strings.TrimSpace(p)})
		}
	}
	// Header规则作为根路径任务添加
	for _, rule := range headerOnlyRules {
		tasks = append(tasks, task{rule: rule, path: "/"})
	}

	// 并发控制
	concurrency := e.config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	// 任务通道
	taskChan := make(chan task, len(tasks))
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	var wg sync.WaitGroup

	// 启动固定数量的工作协程
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case tk, ok := <-taskChan:
					if !ok {
						return
					}

					probeURL := joinURLPath(baseURL, tk.path)

					// 构造Headers
					var headers map[string]string
					if tk.rule.HasHeaders() {
						headers = tk.rule.GetHeaderMap()
					}

					// 发起请求
					body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, probeURL, headers)
					if err != nil {
						continue
					}

					// 构造响应对象
					resp := &HTTPResponse{
						URL:             probeURL,
						Method:          "GET",
						StatusCode:      statusCode,
						ResponseHeaders: make(map[string][]string),
						Body:            body,
						ContentType:     "text/html",
						ContentLength:   int64(len(body)),
						Title:           shared.ExtractTitle(body),
					}

					// 匹配规则
					dslCtx := e.createDSLContextWithClient(resp, httpClient, baseURL)
					if match := e.matchRule(tk.rule, dslCtx); match != nil {
						resultsMu.Lock()
						results = append(results, &ProbeResult{
							Response: resp,
							Matches:  []*FingerprintMatch{match},
						})
						resultsMu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// ExecuteIconProbing 执行Icon主动探测（同步返回结果）
func (e *Engine) ExecuteIconProbing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) (*ProbeResult, error) {
	logger.Debugf("开始Icon主动探测: %s", baseURL)

	// 获取Icon规则
	iconRules := e.ruleManager.GetIconRules()
	if len(iconRules) == 0 {
		return nil, nil
	}

	_, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL解析失败: %v", err)
	}

	// 构造一个虚拟的HTTPResponse，用于传递BaseURL等信息
	resp := &HTTPResponse{
		URL:             baseURL,
		Method:          "GET",
		StatusCode:      200,
		ResponseHeaders: make(map[string][]string),
		Body:            "",
		Title:           "",
	}

	// 创建DSL上下文
	dslCtx := e.createDSLContextWithClient(resp, httpClient, baseURL)

	var matches []*FingerprintMatch

	// 遍历Icon规则并匹配
	for _, rule := range iconRules {
		if match := e.matchRule(rule, dslCtx); match != nil {
			matches = append(matches, match)
		}
	}

	if len(matches) > 0 {
		return &ProbeResult{
			Response: resp,
			Matches:  matches,
		}, nil
	}

	return nil, nil
}

// Execute404Probing 执行404页面探测（同步返回结果）
func (e *Engine) Execute404Probing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) (*ProbeResult, error) {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL解析失败: %v", err)
	}
	scheme := parsedURL.Scheme
	host := parsedURL.Host
	notFoundURL := fmt.Sprintf("%s://%s/404test", scheme, host)

	// 发起请求
	body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, notFoundURL, nil)
	if err != nil {
		return nil, err
	}

	resp := &HTTPResponse{
		URL:             notFoundURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string),
		Body:            body,
		ContentType:     "text/html",
		ContentLength:   int64(len(body)),
		Title:           shared.ExtractTitle(body),
	}

	// 全量匹配
	matches := e.match404PageFingerprints(resp, httpClient, baseURL)
	if len(matches) > 0 {
		return &ProbeResult{
			Response: resp,
			Matches:  matches,
		}, nil
	}

	return nil, nil
}

// match404PageFingerprints 对404页面进行全量指纹规则匹配
func (e *Engine) match404PageFingerprints(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) []*FingerprintMatch {
	logger.Debugf("开始404页面全量指纹匹配")

	// 创建DSL上下文
	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)

	var matches []*FingerprintMatch

	// 获取所有指纹规则进行匹配
	rules := e.ruleManager.GetRulesSnapshot()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
			logger.Debugf("404页面匹配到指纹: %s (规则: %s)",
				match.Technology, match.RuleName)
		}
	}

	logger.Debugf("404页面全量匹配完成，共匹配到 %d 个指纹", len(matches))
	return matches
}

func makeRequestWithOptionalHeaders(httpClient httpclient.HTTPClientInterface, targetURL string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := httpClient.(httpclient.HeaderAwareClient); ok {
			return headerClient.MakeRequestWithHeaders(targetURL, headers)
		}
		logger.Debugf("HTTP客户端不支持自定义头部，使用默认请求: %s", targetURL)
	}

	return httpClient.MakeRequest(targetURL)
}

func joinURLPath(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	base := strings.TrimRight(baseURL, "/")
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return base + "/"
	}

	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	return base + cleanPath
}
