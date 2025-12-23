package dirscan

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
)

// 引擎实现

// NewEngine 创建新的目录扫描引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	}

	engine := &Engine{
		config: config,
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}

	logger.Debug("目录扫描引擎初始化完成")
	return engine
}

// SetProxy 设置代理
func (e *Engine) SetProxy(proxyURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config.ProxyURL = proxyURL
}

// SetFilterConfig 设置自定义过滤器配置（SDK可用）
func (e *Engine) SetFilterConfig(cfg *FilterConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.filterConfig = CloneFilterConfig(cfg)
}

func (e *Engine) getFilterConfig() *FilterConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.filterConfig == nil {
		return nil
	}
	return CloneFilterConfig(e.filterConfig)
}

// GetLastScanResult 获取最后一次扫描结果
func (e *Engine) GetLastScanResult() *ScanResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.lastScanResult == nil {
		return nil
	}

	// 返回副本
	result := *e.lastScanResult
	return &result
}

// ClearResults 清空结果
func (e *Engine) ClearResults() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastScanResult = nil

	logger.Debug("扫描结果已清空")
}

// PerformScan 执行扫描
func (e *Engine) PerformScan(collectorInstance interfaces.URLCollectorInterface) (*ScanResult, error) {
	return e.PerformScanWithOptions(collectorInstance, false)
}

// PerformScanWithFilter 执行扫描（支持自定义过滤器）
func (e *Engine) PerformScanWithFilter(collectorInstance interfaces.URLCollectorInterface, recursive bool, filter *ResponseFilter) (*ScanResult, error) {
	e.mu.Lock()
	if e.stats == nil {
		e.stats = &Statistics{StartTime: time.Now()}
	}
	e.mu.Unlock()

	startTime := time.Now()

	// 1. 生成扫描URL
	scanURLs, err := e.generateScanURLs(collectorInstance, recursive)
	if err != nil {
		return nil, fmt.Errorf("生成扫描URL失败: %v", err)
	}

	if len(scanURLs) == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	logger.Debugf("生成扫描URL: %d个", len(scanURLs))
	atomic.StoreInt64(&e.stats.TotalGenerated, int64(len(scanURLs)))

	// 2. 初始化过滤器
	var responseFilter *ResponseFilter
	if filter != nil {
		responseFilter = filter
	} else if cfg := e.getFilterConfig(); cfg != nil {
		responseFilter = NewResponseFilter(cfg)
	} else {
		responseFilter = CreateResponseFilterFromExternal()
	}

	// [修复] 注入 HTTP 客户端以支持 icon() 等主动探测指纹
	if responseFilter != nil {
		processor := e.getOrCreateRequestProcessor()
		responseFilter.SetHTTPClient(processor)
	}

	// 准备累积结果和锁
	finalFilterResult := &interfaces.FilterResult{
		ValidPages:           make([]*interfaces.HTTPResponse, 0),
		PrimaryFilteredPages: make([]*interfaces.HTTPResponse, 0),
		StatusFilteredPages:  make([]*interfaces.HTTPResponse, 0),
	}
	var resultMu sync.Mutex

	// 3. 执行HTTP请求（带实时过滤回调）
	actualConcurrency := e.getActualConcurrency()
	logger.Infof("%d URL，Threads: %d，Random UA: true", len(scanURLs), actualConcurrency)

	responses, err := e.performHTTPRequestsWithCallback(scanURLs, func(resp *interfaces.HTTPResponse) {
		if resp == nil {
			return
		}
		// 转换并过滤
		// 注意：这里我们构造一个单元素的切片进行处理
		// [优化] 现在 FilterResponses 接收 []*HTTPResponse，直接传递即可
		filterInput := []*interfaces.HTTPResponse{resp}
		singleResult := responseFilter.FilterResponses(filterInput)
		if singleResult == nil {
			logger.Warnf("ResponseFilter.FilterResponses returned nil for URL: %s", resp.URL)
			return
		}

		// 实时输出有效页面
		// 累积结果 (线程安全)
		resultMu.Lock()
		if len(singleResult.ValidPages) > 0 {
			finalFilterResult.ValidPages = append(finalFilterResult.ValidPages, singleResult.ValidPages...)
		}
		if len(singleResult.PrimaryFilteredPages) > 0 {
			finalFilterResult.PrimaryFilteredPages = append(finalFilterResult.PrimaryFilteredPages, singleResult.PrimaryFilteredPages...)
		}
		if len(singleResult.StatusFilteredPages) > 0 {
			finalFilterResult.StatusFilteredPages = append(finalFilterResult.StatusFilteredPages, singleResult.StatusFilteredPages...)
		}
		resultMu.Unlock()
	})

	if err != nil {
		return nil, fmt.Errorf("HTTP请求执行失败: %v", err)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("没有收到有效的HTTP响应")
	}

	logger.Debugf("HTTP扫描完成，收到 %d 个响应", len(responses))
	atomic.StoreInt64(&e.stats.TotalRequests, int64(len(responses)))

	// 补充：收集无效页面哈希统计 (从过滤器中获取最终状态)
	if responseFilter != nil {
		finalFilterResult.InvalidPageHashes = responseFilter.GetInvalidPageHashes()
	}
	// 注意：这里我们假设过滤器是 HashFilter，如果接口支持的话
	// 实际上 ResponseFilter 封装了这些细节，但 GetHashFilter 方法在 ResponseFilter 中有导出

	atomic.StoreInt64(&e.stats.FilteredResults, int64(len(finalFilterResult.ValidPages)))
	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		len(responses), len(finalFilterResult.ValidPages))

	// 4. 创建扫描结果
	endTime := time.Now()
	result := &ScanResult{
		Target:        e.extractTarget(responses),
		CollectedURLs: []string{}, // 不再维护收集的URL列表
		ScanURLs:      scanURLs,
		Responses:     responses,
		FilterResult:  finalFilterResult,
		StartTime:     startTime,
		EndTime:       endTime,
		Duration:      endTime.Sub(startTime),
	}

	// 5. 更新统计信息
	e.mu.Lock()
	e.lastScanResult = result
	e.stats.LastScanTime = endTime
	atomic.AddInt64(&e.stats.TotalScans, 1)
	atomic.StoreInt64(&e.stats.ValidResults, int64(len(finalFilterResult.ValidPages)))
	e.mu.Unlock()

	logger.Debugf("扫描执行完成，耗时: %v", result.Duration)
	return result, nil
}

// PerformScanWithOptions 执行扫描（支持选项）
func (e *Engine) PerformScanWithOptions(collectorInstance interfaces.URLCollectorInterface, recursive bool) (*ScanResult, error) {
	return e.PerformScanWithFilter(collectorInstance, recursive, nil)
}

// ScanExactURLs 对指定的URL列表执行扫描（不进行字典生成）
// 专门用于递归验证或精确目标扫描
func (e *Engine) ScanExactURLs(urls []string) ([]*interfaces.HTTPResponse, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	logger.Debugf("执行精确URL扫描: %d 个", len(urls))

	// 直接调用 HTTP 请求执行逻辑
	responses, err := e.performHTTPRequests(urls)
	if err != nil {
		return nil, err
	}

	return responses, nil
}

// generateScanURLs 生成扫描URL
func (e *Engine) generateScanURLs(collectorInstance interfaces.URLCollectorInterface, recursive bool) ([]string, error) {
	logger.Debug("开始生成扫描URL")

	// 创建URL生成器
	generator := NewURLGenerator()

	// 生成扫描URL
	// [修改] 传递 recursive 参数
	scanURLs := generator.GenerateURLsFromCollector(collectorInstance, recursive)

	logger.Debugf("生成扫描URL完成，共%d个", len(scanURLs))
	return scanURLs, nil
}

// performHTTPRequestsWithCallback 执行HTTP请求（支持回调）
func (e *Engine) performHTTPRequestsWithCallback(scanURLs []string, callback func(*interfaces.HTTPResponse)) ([]*interfaces.HTTPResponse, error) {
	logger.Debug("开始执行HTTP扫描 (Callback模式)")

	// 获取或创建请求处理器
	processor := e.getOrCreateRequestProcessor()

	// 执行请求
	responses := processor.ProcessURLsWithCallback(scanURLs, callback)

	atomic.StoreInt64(&e.stats.SuccessRequests, int64(len(responses)))

	return responses, nil
}

// performHTTPRequests 执行HTTP请求
func (e *Engine) performHTTPRequests(scanURLs []string) ([]*interfaces.HTTPResponse, error) {
	return e.performHTTPRequestsWithCallback(scanURLs, nil)
}

// getOrCreateRequestProcessor 获取或创建请求处理器
func (e *Engine) getOrCreateRequestProcessor() *requests.RequestProcessor {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.requestProcessor == nil {
		logger.Debug("创建新的请求处理器")
		e.requestProcessor = requests.NewRequestProcessor(nil)
	}

	// [重构] 强制设置配置，不依赖于之前的状态，确保幂等性
	reqConfig := e.requestProcessor.GetConfig()

	// 1. 始终应用代理配置（如果有）
	if e.config.ProxyURL != "" {
		reqConfig.ProxyURL = e.config.ProxyURL
	}

	// 2. 始终强制开启重定向跟随，且至少允许5次跳转
	// 这是目录扫描的核心需求：必须看到最终页面才能正确去重
	reqConfig.FollowRedirect = true
	if reqConfig.MaxRedirects < 5 {
		reqConfig.MaxRedirects = 5
	}

	// 3. 直接更新，无需条件判断，确保配置绝对生效
	e.requestProcessor.UpdateConfig(reqConfig)

	return e.requestProcessor
}

// SetCustomHeaders 设置自定义HTTP头部
func (e *Engine) SetCustomHeaders(headers map[string]string) {
	processor := e.getOrCreateRequestProcessor()
	processor.SetCustomHeaders(headers)
	logger.Debugf("应用了 %d 个自定义HTTP头部到请求处理器", len(headers))
}

// getActualConcurrency 获取实际的并发数（用于日志显示）
func (e *Engine) getActualConcurrency() int {
	// 使用默认配置的并发数
	processor := e.getOrCreateRequestProcessor()
	if processor != nil {
		if cfg := processor.GetConfig(); cfg != nil && cfg.MaxConcurrent > 0 {
			return cfg.MaxConcurrent
		}
	}

	// 最后的备用值
	return 50
}

// applyFilter 应用过滤器
func (e *Engine) applyFilter(responses []*interfaces.HTTPResponse, externalFilter *ResponseFilter) (*interfaces.FilterResult, error) {
	logger.Debug("开始应用响应过滤器")

	var responseFilter *ResponseFilter
	if externalFilter != nil {
		responseFilter = externalFilter
	} else if cfg := e.getFilterConfig(); cfg != nil {
		responseFilter = NewResponseFilter(cfg)
	} else {
		responseFilter = CreateResponseFilterFromExternal()
	}

	// [修复] 注入 HTTP 客户端以支持 icon() 等主动探测指纹
	if responseFilter != nil {
		processor := e.getOrCreateRequestProcessor()
		responseFilter.SetHTTPClient(processor)
	}

	// 转换为过滤器可处理的格式
	// [优化] 直接传递指针切片，convertToFilterResponses 已废弃或修改
	// filterResponses := e.convertToFilterResponses(responses)

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)

	return filterResult, nil
}

// convertToFilterResponses 转换响应格式（内存优化版本）
// [已废弃] FilterResponses 现在直接接收 []*HTTPResponse，无需转换
func (e *Engine) convertToFilterResponses(httpResponses []*interfaces.HTTPResponse) []interfaces.HTTPResponse {
	filterResponses := make([]interfaces.HTTPResponse, len(httpResponses))
	for i, resp := range httpResponses {
		// 内存优化：只复制过滤器真正需要的核心字段
		// [修复] 必须包含 ResponseHeaders，否则 header() 指纹规则和解压缩逻辑会失效
		filterResponses[i] = interfaces.HTTPResponse{
			URL:             resp.URL,                   // 结果展示需要
			StatusCode:      resp.StatusCode,            // 状态码过滤器使用
			ContentLength:   resp.ContentLength,         // 哈希过滤器容错计算使用
			ContentType:     resp.ContentType,           // Content-Type过滤器使用
			Title:           resp.Title,                 // 哈希过滤器生成页面哈希使用
			Body:            e.getFilterBody(resp.Body), // 哈希计算使用（已截断）
			ResponseHeaders: resp.ResponseHeaders,       // 指纹识别 header() 规则需要
			// 内存优化：其他字段使用零值，大幅减少内存占用
			// Method、Server、IsDirectory、Length、Duration、Depth等字段在过滤器中未使用
		}
	}
	return filterResponses
}

// getFilterBody 获取用于过滤的响应体（内存优化）
func (e *Engine) getFilterBody(body string) string {
	// 过滤器只需要响应体的前部分用于哈希计算
	const maxFilterBodySize = 4096 // 4KB足够用于过滤判断
	if len(body) > maxFilterBodySize {
		return body[:maxFilterBodySize]
	}
	return body
}

// extractTarget 提取目标信息
func (e *Engine) extractTarget(responses []*interfaces.HTTPResponse) string {
	if len(responses) == 0 {
		return "unknown"
	}

	// 从第一个响应中提取主机信息
	firstURL := responses[0].URL
	if firstURL == "" {
		return "unknown"
	}

	// 简单提取主机部分
	if len(firstURL) > 50 {
		return firstURL[:50] + "..."
	}
	return firstURL
}
