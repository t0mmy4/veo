package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/progress"
)

func (sc *ScanController) runFingerprintModuleWithContext(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalDecompress := true
	originalFollowRedirect := false
	originalMaxRedirects := 0
	if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
		originalDecompress = cfg.DecompressResponse
		originalFollowRedirect = cfg.FollowRedirect
		originalMaxRedirects = cfg.MaxRedirects

		needsUpdate := !cfg.DecompressResponse || !cfg.FollowRedirect || cfg.MaxRedirects != requests.DefaultMaxRedirects
		if needsUpdate {
			updated := *cfg
			updated.DecompressResponse = true
			requests.ApplyRedirectPolicy(&updated)
			sc.requestProcessor.UpdateConfig(&updated)
		}
	}

	defer func() {
		if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
			if cfg.DecompressResponse != originalDecompress || cfg.FollowRedirect != originalFollowRedirect || cfg.MaxRedirects != originalMaxRedirects {
				updated := *cfg
				updated.DecompressResponse = originalDecompress
				updated.FollowRedirect = originalFollowRedirect
				updated.MaxRedirects = originalMaxRedirects
				sc.requestProcessor.UpdateConfig(&updated)
			}
		}
	}()

	fmt.Println()
	if sc.fingerprintEngine != nil {
		summary := sc.fingerprintEngine.GetLoadedSummaryString()
		if summary != "" {
			logger.Infof("Start FingerPrint, Loaded FingerPrint Rules: %s", summary)
		} else {
			logger.Infof("Start FingerPrint")
		}
	} else {
		logger.Infof("Start FingerPrint")
	}
	logger.Debugf("开始指纹识别，数量: %d", len(targets))

	if sc.requestProcessor != nil {
		originalRedirectScope := sc.requestProcessor.IsRedirectSameHostOnly()
		sc.requestProcessor.SetRedirectSameHostOnly(false)
		defer sc.requestProcessor.SetRedirectSameHostOnly(originalRedirectScope)
	}

	return sc.runConcurrentFingerprintWithContext(ctx, targets)
}

func (sc *ScanController) runConcurrentFingerprintWithContext(parentCtx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("并发指纹识别模式，数量: %d", len(targets))

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxConcurrent)

	var progressTracker *progress.RequestProgress
	totalRequests := int64(len(targets))
	if sc.fingerprintEngine != nil && sc.args != nil && !sc.args.NoProbe {
		activeTargets := len(sc.getUniqueProbeTargets(targets))
		if activeTargets > 0 {
			activeRequests := activeTargets
			if sc.fingerprintEngine.HasPathRules() {
				pathCount := sc.fingerprintEngine.GetPathRulesCount()
				headerCount := sc.fingerprintEngine.GetHeaderRulesCount()
				activeRequests = activeTargets * (pathCount + headerCount + 1)
			}
			if len(sc.fingerprintEngine.GetIconRules()) > 0 {
				activeRequests += activeTargets
			}
			totalRequests += int64(activeRequests)
		}
	}
	if totalRequests > 0 {
		showProgress := true
		if sc.args != nil && sc.args.JSONOutput {
			showProgress = false
		}
		if updater := sc.requestProcessor.GetStatsUpdater(); updater != nil {
			if enabled, ok := updater.(interface{ IsEnabled() bool }); ok && enabled.IsEnabled() {
				showProgress = false
			}
		}
		if showProgress {
			label := sc.buildFingerprintProgressLabel(targets)
			if label != "" {
				progressTracker = progress.NewRequestProgress(label, totalRequests, true)
			}
		}
	}

	jobs := make(chan string, len(targets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				taskTimeout := sc.requestProcessor.GetConfig().Timeout
				targetCtx, targetCancel := context.WithTimeout(ctx, taskTimeout)
				results := sc.processSingleTargetFingerprintWithContext(targetCtx, targetURL, progressTracker)
				targetCancel()

				resultsChan <- results

				// 更新统计
				if sc.statsDisplay.IsEnabled() {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}
		}()
	}

	// 提交任务
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	// 结果收集协程
	done := make(chan struct{})
	go func() {
		for resList := range resultsChan {
			if len(resList) > 0 {
				resultsMu.Lock()
				allResults = append(allResults, resList...)
				resultsMu.Unlock()
			}
		}
		close(done)
	}()

	// 等待所有 Worker 完成
	wg.Wait()
	close(resultsChan)

	// 等待结果收集完成
	<-done

	// 主动探测 (Path, Icon, 404)
	activeResults := sc.performActiveProbing(ctx, targets, progressTracker)
	if len(activeResults) > 0 {
		allResults = append(allResults, activeResults...)
	}

	if progressTracker != nil {
		progressTracker.Stop()
	}

	return allResults, nil
}

// processSingleTargetFingerprintWithContext 处理单个目标，支持传入 Context
func (sc *ScanController) processSingleTargetFingerprintWithContext(ctx context.Context, target string, progressTracker *progress.RequestProgress) []interfaces.HTTPResponse {
	// 使用channel接收结果以支持select超时
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("指纹识别panic: %v, 目标: %s", r, target)
				resultChan <- nil
			}
		}()

		resultChan <- sc.processSingleTargetFingerprint(ctx, target, progressTracker)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-ctx.Done():
		logger.Debugf("目标处理超时: %s", target)
		return nil
	}
}

// processSingleTargetFingerprint 处理单个目标的指纹识别（多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(ctx context.Context, target string, progressTracker *progress.RequestProgress) []interfaces.HTTPResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	logger.Debugf("开始处理指纹识别: %s", target)

	// 为目标设置上下文
	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	var results []interfaces.HTTPResponse

	if sc.requestProcessor == nil || sc.fingerprintEngine == nil {
		return results
	}

	resp, err := sc.requestProcessor.RequestOnceWithHeaders(ctx, target, nil)
	if progressTracker != nil {
		progressTracker.Increment()
	}
	if err != nil || resp == nil {
		return results
	}

	fpResponse := sc.convertToFingerprintResponse(resp)
	if fpResponse == nil {
		logger.Debugf("响应转换失败: %s", resp.URL)
		return results
	}

	matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, sc.requestProcessor)
	httpResp := interfaces.HTTPResponse{
		URL:             resp.URL,
		StatusCode:      resp.StatusCode,
		ContentLength:   resp.ContentLength,
		ContentType:     resp.ContentType,
		ResponseHeaders: resp.ResponseHeaders,
		RequestHeaders:  resp.RequestHeaders,
		ResponseBody:    resp.ResponseBody,
		Title:           resp.Title,
		Server:          resp.Server,
		Duration:        resp.Duration,
		IsDirectory:     false,
	}
	if len(matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(matches, true)
	}
	results = append(results, httpResp)
	logger.Debugf("%s 识别完成: %d", target, len(matches))

	return results
}

func (sc *ScanController) buildFingerprintProgressLabel(targets []string) string {
	if len(targets) == 1 {
		return sc.extractBaseURL(targets[0])
	}
	return "Fingerprint"
}

type progressHTTPClient struct {
	base      httpclient.HTTPClientInterface
	header    httpclient.HeaderAwareClient
	onRequest func()
}

func (c *progressHTTPClient) MakeRequest(rawURL string) (string, int, error) {
	body, statusCode, err := c.base.MakeRequest(rawURL)
	if c.onRequest != nil {
		c.onRequest()
	}
	return body, statusCode, err
}

func (c *progressHTTPClient) MakeRequestWithHeaders(rawURL string, headers map[string]string) (string, int, error) {
	if c.header != nil {
		body, statusCode, err := c.header.MakeRequestWithHeaders(rawURL, headers)
		if c.onRequest != nil {
			c.onRequest()
		}
		return body, statusCode, err
	}

	body, statusCode, err := c.base.MakeRequest(rawURL)
	if c.onRequest != nil {
		c.onRequest()
	}
	return body, statusCode, err
}

func (sc *ScanController) wrapProgressHTTPClient(base httpclient.HTTPClientInterface, progressTracker *progress.RequestProgress) httpclient.HTTPClientInterface {
	if base == nil || progressTracker == nil {
		return base
	}

	client := &progressHTTPClient{
		base:      base,
		onRequest: progressTracker.Increment,
	}
	if header, ok := base.(httpclient.HeaderAwareClient); ok {
		client.header = header
	}
	return client
}

// printFingerprintResultWithProgressClear 输出指纹结果并清除进度条（Helper function for DRY）
func (sc *ScanController) printFingerprintResultWithProgressClear(matches []*fingerprint.FingerprintMatch, response *fingerprint.HTTPResponse, formatter fingerprint.OutputFormatter, tag string) {
	if formatter != nil && len(matches) > 0 {
		// Clear progress bar line if needed
		if !sc.args.JSONOutput && sc.args.Stats {
			fmt.Printf("\r\033[K")
		}
		// Use original formatter
		formatter.FormatMatch(matches, response, tag)
	}
}

// performActiveProbing 执行主动探测（Path, Icon, 404）
func (sc *ScanController) performActiveProbing(ctx context.Context, targets []string, progressTracker *progress.RequestProgress) []interfaces.HTTPResponse {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过主动探测")
		return nil
	}

	if sc.args != nil && sc.args.NoProbe {
		logger.Debug("已禁用主动探测 (--no-probe)")
		return nil
	}

	// 检查Context是否取消
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// 检查是否有任何需要主动探测的规则
	hasPathRules := sc.fingerprintEngine.HasPathRules()
	hasIconRules := len(sc.fingerprintEngine.GetIconRules()) > 0

	var allResults []interfaces.HTTPResponse

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	uniqueTargets := sc.getUniqueProbeTargets(targets)

	if len(uniqueTargets) == 0 {
		logger.Debug("所有目标主机均已探测过或无需探测，跳过主动探测阶段")
		return nil
	}

	outerConcurrent := maxConcurrent

	formatter := sc.fingerprintEngine.GetOutputFormatter()
	probeClient := sc.wrapProgressHTTPClient(sc.requestProcessor, progressTracker)

	jobs := make(chan string, len(uniqueTargets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(uniqueTargets))

	var wg sync.WaitGroup

	for i := 0; i < outerConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for baseURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				var localResults []interfaces.HTTPResponse
				probeKey := baseURL

				if sc.shouldTriggerPathProbing(probeKey) {
					logger.Debugf("触发主动探测: %s", probeKey)
					sc.markHostAsProbed(probeKey)

					probeTimeout := sc.requestProcessor.GetConfig().Timeout
					probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)

					// 1. Path Probing
					if hasPathRules {
						results, err := sc.fingerprintEngine.ExecuteActiveProbing(probeCtx, baseURL, probeClient)
						if err != nil {
							logger.Debugf("Path probing error: %v", err)
						}
						if len(results) > 0 {
							if formatter != nil {
								for _, res := range results {
									sc.printFingerprintResultWithProgressClear(res.Matches, res.Response, formatter, "Path探测")
								}
							}
							for _, res := range results {
								httpResp := sc.convertProbeResult(res)
								localResults = append(localResults, httpResp)
							}
						}
					}

					// Icon Probing
					if hasIconRules {
						iconBaseURL := sc.extractBaseURL(baseURL)
						if iconBaseURL == "" {
							iconBaseURL = baseURL
						}
						if resIcon, err := sc.fingerprintEngine.ExecuteIconProbing(probeCtx, iconBaseURL, probeClient); err != nil {
							logger.Debugf("Icon probing error: %v", err)
						} else if resIcon != nil {
							if formatter != nil {
								sc.printFingerprintResultWithProgressClear(resIcon.Matches, resIcon.Response, formatter, "icon探测")
							}
							httpResp := sc.convertProbeResult(resIcon)
							localResults = append(localResults, httpResp)
						}
					}

					// 404 Page Probing
					if res404 := sc.perform404PageProbing(probeCtx, baseURL, formatter, probeClient); res404 != nil {
						localResults = append(localResults, *res404)
					}

					cancel()
				} else {
					logger.Debugf("目标已探测过，跳过主动探测: %s", probeKey)
				}
				resultsChan <- localResults
			}
		}()
	}

	// 提交任务
	for _, baseURL := range uniqueTargets {
		jobs <- baseURL
	}
	close(jobs)

	// 收集结果协程
	resDone := make(chan struct{})
	go func() {
		for res := range resultsChan {
			if len(res) > 0 {
				allResults = append(allResults, res...)
			}
		}
		close(resDone)
	}()

	wg.Wait()
	close(resultsChan)
	<-resDone

	return allResults
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(ctx context.Context, baseURL string, formatter fingerprint.OutputFormatter, client httpclient.HTTPClientInterface) *interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		return nil
	}

	// 策略：完全使用全局超时配置
	probeTimeout := sc.requestProcessor.GetConfig().Timeout
	// 使用传入的 ctx 作为父 Context
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if client == nil {
		client = sc.requestProcessor
	}
	result, err := sc.fingerprintEngine.Execute404Probing(probeCtx, baseURL, client)
	if err != nil {
		logger.Debugf("404 probing error: %v", err)
		return nil
	}

	if result != nil {
		// 使用 Helper 输出结果
		sc.printFingerprintResultWithProgressClear(result.Matches, result.Response, formatter, "404探测")

		httpResp := sc.convertProbeResult(result)
		return &httpResp
	}

	return nil
}

func (sc *ScanController) convertProbeResult(result *fingerprint.ProbeResult) interfaces.HTTPResponse {
	resp := result.Response
	httpResp := interfaces.HTTPResponse{
		URL:           resp.URL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.ContentType,
		ResponseBody:  resp.Body,
		Title:         resp.Title,
		IsDirectory:   false,
	}
	if len(result.Matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(result.Matches, true)
	}
	return httpResp
}

func extractDomainFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	if len(rawURL) > 30 {
		return rawURL[:27] + "..."
	}
	return rawURL
}

// shouldTriggerPathProbing 检查是否应该触发path探测
func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()

	// 检查是否已经探测过此主机
	return !sc.probedHosts[hostKey]
}

// getUniqueProbeTargets 提取唯一探测目标（Helper method）
func (sc *ScanController) getUniqueProbeTargets(targets []string) map[string]string {
	uniqueTargets := make(map[string]string)
	for _, t := range targets {
		// 策略：对于每个目标，我们总是尝试探测其根目录
		rootURL := sc.extractBaseURL(t)
		if sc.shouldTriggerPathProbing(rootURL) {
			uniqueTargets[rootURL] = rootURL
		}

		// 如果目标包含路径（且不等于根目录），我们也探测该路径
		fullURL := sc.extractBaseURLWithPath(t)
		// 简单比较：移除末尾斜杠后再比较，避免 http://x/ 和 http://x 视为不同
		if strings.TrimRight(fullURL, "/") != strings.TrimRight(rootURL, "/") {
			if sc.shouldTriggerPathProbing(fullURL) {
				uniqueTargets[fullURL] = fullURL
			}
		}
	}
	return uniqueTargets
}

// markHostAsProbed 标记主机为已探测
func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}
