package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"veo/internal/scheduler"
	"veo/pkg/dirscan"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

func (sc *ScanController) runDirscanModule(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")

	// [修复] 开启批量模式，确保递归扫描时 TotalRequests 正确累加而不是重置
	// 避免出现 Requests: 4000/2000 (200%) 的情况
	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)

	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
		sc.requestProcessor.SetBatchMode(originalBatchMode)
	}()

	// [强制配置] 在运行目录扫描前，强制更新 RequestProcessor 的重定向配置
	reqConfig := sc.requestProcessor.GetConfig()
	if !reqConfig.FollowRedirect || reqConfig.MaxRedirects < 3 {
		reqConfig.FollowRedirect = true
		if reqConfig.MaxRedirects < 3 {
			reqConfig.MaxRedirects = 5
		}
		sc.requestProcessor.UpdateConfig(reqConfig)
		logger.Debug("Dirscan模块运行前强制启用重定向跟随 (MaxRedirects=5)")
	}

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	logger.Debugf("开始目录扫描，目标数量: %d", len(targets))

	// 定义层级扫描器
	layerScanner := func(layerTargets []string, filter *dirscan.ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
		recursive := depth > 0
		// 多目标优化：判断是否使用并发扫描
		if len(layerTargets) > 1 {
			return sc.runConcurrentDirscan(ctx, layerTargets, filter, recursive)
		} else {
			return sc.runSequentialDirscan(ctx, layerTargets, filter, recursive)
		}
	}

	// 定义数据获取器（用于目录验证）
	fetcher := func(urls []string) []interfaces.HTTPResponse {
		// 检查Context取消
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		responses := sc.requestProcessor.ProcessURLsWithContext(ctx, urls)
		var result []interfaces.HTTPResponse
		for _, r := range responses {
			if r != nil {
				result = append(result, *r)
			}
		}
		return result
	}

	// 执行递归扫描
	var allResults []interfaces.HTTPResponse
	var recursiveFilter *dirscan.ResponseFilter = nil
	maxDepth := sc.args.Depth

	allResults, _ = dirscan.RunRecursiveScan(
		ctx,
		targets,
		maxDepth,
		layerScanner,
		fetcher,
		recursiveFilter,
	)

	return allResults, nil
}

func (sc *ScanController) runConcurrentDirscan(ctx context.Context, targets []string, filter *dirscan.ResponseFilter, recursive bool) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("目标数量: %d", len(targets))

	// 创建目标调度器
	scheduler := scheduler.NewTargetScheduler(ctx, targets, sc.config)
	scheduler.SetRecursive(recursive)

	// [新增] 传递CLI超时设置给调度器
	if sc.timeoutSeconds > 0 {
		scheduler.SetRequestTimeout(time.Duration(sc.timeoutSeconds) * time.Second)
	}

	// 设置基础请求处理器，确保统计更新正常工作
	scheduler.SetBaseRequestProcessor(sc.requestProcessor)

	// [新增] 实时结果处理回调
	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex

	// 启动独立的打印协程
	printChan := make(chan *interfaces.HTTPResponse, 100)
	printWg := sync.WaitGroup{}
	printWg.Add(1)
	go sc.startResultPrinter(printChan, &printWg, filter)

	scheduler.SetResultCallback(func(target string, resp *interfaces.HTTPResponse) {
		sc.handleRealTimeResult(ctx, target, resp, filter, &allResults, &resultsMu, printChan)
	})

	// 执行并发扫描
	// 注意：虽然 ExecuteConcurrentScan 返回所有原始结果，但我们已经在回调中处理了有效结果
	_, err := scheduler.ExecuteConcurrentScan()

	// 关闭打印通道并等待打印完成
	close(printChan)
	printWg.Wait()

	if err != nil {
		return nil, fmt.Errorf("多目标并发扫描失败: %v", err)
	}

	return allResults, nil
}

func (sc *ScanController) runSequentialDirscan(ctx context.Context, targets []string, filter *dirscan.ResponseFilter, recursive bool) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	// 启动独立的打印协程
	printChan := make(chan *interfaces.HTTPResponse, 100)
	printWg := sync.WaitGroup{}
	printWg.Add(1)
	go sc.startResultPrinter(printChan, &printWg, filter)

	defer func() {
		close(printChan)
		printWg.Wait()
	}()

	for _, target := range targets {
		// 检查Context取消
		select {
		case <-ctx.Done():
			logger.Warn("扫描已取消，停止顺序扫描")
			return allResults, nil
		default:
		}

		// 生成扫描URL
		scanURLs := sc.generateDirscanURLs(target, recursive)
		logger.Debugf("为 %s 生成了 %d 个扫描URL", target, len(scanURLs))

		// [调试] 打印生成的URL示例（前5个）
		if len(scanURLs) > 0 {
			count := 5
			if len(scanURLs) < count {
				count = len(scanURLs)
			}
			logger.Debugf("生成的URL示例 (Top %d):", count)
			for i := 0; i < count; i++ {
				logger.Debugf("  - %s", scanURLs[i])
			}
		}

		// 发起HTTP请求（实时处理）
		// 使用支持 ctx 的版本，确保 Ctrl+C 能尽快停止当前目标的剩余URL派发
		sc.requestProcessor.ProcessURLsWithCallbackWithContext(ctx, scanURLs, func(resp *interfaces.HTTPResponse) {
			sc.handleRealTimeResult(ctx, target, resp, filter, &allResults, nil, printChan)
		})

		// 更新已完成主机数统计（单目标扫描）
		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标扫描完成目标 %s，更新已完成主机数", target)
		}
	}
	return allResults, nil
}

func (sc *ScanController) generateDirscanURLs(target string, recursive bool) []string {
	parsedURL, err := url.Parse(target)
	if err != nil {
		logger.Errorf("URL解析失败: %v", err)
		return []string{target}
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	path := strings.Trim(parsedURL.Path, "/")
	if path == "" {
		if recursive {
			return sc.urlGenerator.GenerateRecursiveURLs([]string{baseURL})
		}
		return sc.urlGenerator.GenerateURLs([]string{baseURL})
	}

	pathParts := strings.Split(path, "/")
	var scanTargets []string

	currentPath := ""
	for _, part := range pathParts {
		currentPath += "/" + part
		scanTarget := baseURL + currentPath
		if !strings.HasSuffix(scanTarget, "/") {
			scanTarget += "/"
		}
		scanTargets = append(scanTargets, scanTarget)
	}

	if recursive {
		// 递归模式：只扫描最终的目标路径，不生成中间路径的扫描任务
		// 但这里的 scanTargets 生成逻辑其实是把每一层都加进去了
		// 如果是递归模式，我们其实只关心最后一个 scanTarget
		if len(scanTargets) > 0 {
			lastTarget := scanTargets[len(scanTargets)-1]
			return sc.urlGenerator.GenerateRecursiveURLs([]string{lastTarget})
		}
		return sc.urlGenerator.GenerateRecursiveURLs(scanTargets)
	}
	return sc.urlGenerator.GenerateURLs(scanTargets)
}

// handleRealTimeResult 处理实时扫描结果（DRY优化）
func (sc *ScanController) handleRealTimeResult(ctx context.Context, target string, resp *interfaces.HTTPResponse, filter *dirscan.ResponseFilter, results *[]interfaces.HTTPResponse, mu *sync.Mutex, printChan chan<- *interfaces.HTTPResponse) {
	if resp == nil {
		return
	}
	// 调用 processTargetResponses 处理单个响应（包含过滤、去重）
	// 注意：现在不直接打印，而是返回有效页面供后续处理
	validPages, _ := sc.processTargetResponses(ctx, []*interfaces.HTTPResponse{resp}, target, filter)

	if len(validPages) > 0 {
		if mu != nil {
			mu.Lock()
		}

		for i := range validPages {
			page := validPages[i] // 获取指针
			if page == nil {
				continue
			}
			// 添加到结果集（由于 validPages 是指针切片，我们需要解引用来存储值，或者修改 results 类型）
			// 这里 results 是 []interfaces.HTTPResponse (值切片)，为了兼容现有代码结构
			*results = append(*results, *page)

			// 发送到打印通道
			if printChan != nil {
				printChan <- page
			}
		}

		if mu != nil {
			mu.Unlock()
		}
	}
}

// startResultPrinter 启动结果打印协程
func (sc *ScanController) startResultPrinter(printChan <-chan *interfaces.HTTPResponse, wg *sync.WaitGroup, filter *dirscan.ResponseFilter) {
	defer wg.Done()

	for page := range printChan {
		if page == nil {
			continue
		}
		// 使用提取出来的打印逻辑
		sc.printSingleValidPage(page, filter)
	}
}

// printSingleValidPage 打印单个有效页面（从ResponseFilter提取出的逻辑）
func (sc *ScanController) printSingleValidPage(page *interfaces.HTTPResponse, filter *dirscan.ResponseFilter) {
	// 使用已经识别好的指纹信息
	matches := page.Fingerprints
	var fingerprintUnion string

	// 格式化指纹显示
	if len(matches) > 0 {
		// 转换为指针列表以便使用 formatFingerprintMatches (这是一个 hack，因为 formatter 需要 []*Match)
		matchPtrs := make([]*interfaces.FingerprintMatch, len(matches))
		for i := range matches {
			matchPtrs[i] = &matches[i]
		}

		// 暂时还需要访问 filter 获取显示配置，理想情况这应该在 Printer 配置中
		// 但为了最小化改动，我们这里还是复用 filter 的方法，只是逻辑在外部控制
		// 注意：formatFingerprintMatches 是私有方法，我们需要在 filter.go 中公开它或者复制逻辑
		// 这里我们暂时假设 ResponseFilter 还有这个能力，或者我们需要把它移出来
		// 由于 formatFingerprintMatches 是私有的，我们暂时无法直接调用。
		// 我们需要修改 filter.go 将其公开，或者在 cli 包中实现格式化逻辑。
		// 鉴于 KISS 原则，我们在 cli 包中实现一个简单的 wrapper
		fingerprintUnion = sc.formatFingerprintMatches(matchPtrs, sc.showFingerprintRule)
	}

	fingerprintParts := []string{}
	if strings.TrimSpace(fingerprintUnion) != "" {
		fingerprintParts = append(fingerprintParts, fingerprintUnion)
	}

	line := formatter.FormatLogLine(
		page.URL,
		page.StatusCode,
		page.Title,
		page.ContentLength,
		page.ContentType,
		fingerprintParts,
		len(matches) > 0,
	)

	var messageBuilder strings.Builder
	messageBuilder.WriteString(line)

	// 如果 URL 过长（超过 60 字符），在下一行输出完整 URL 方便复制
	if len(page.URL) > 60 {
		messageBuilder.WriteString("\n")
		messageBuilder.WriteString("  └─ ")
		messageBuilder.WriteString(formatter.FormatFullURL(page.URL))
	}

	if sc.showFingerprintSnippet && len(matches) > 0 {
		var snippetLines []string
		for _, m := range matches {
			snippet := strings.TrimSpace(m.Snippet)
			if snippet == "" {
				continue
			}
			highlighted := formatter.HighlightSnippet(snippet, m.Matcher)
			if highlighted == "" {
				continue
			}
			snippetLines = append(snippetLines, highlighted)
		}
		if len(snippetLines) > 0 {
			messageBuilder.WriteString("\n")
			for idx, snippetLine := range snippetLines {
				if idx > 0 {
					messageBuilder.WriteString("\n")
				}
				messageBuilder.WriteString("  ")
				messageBuilder.WriteString(formatter.FormatSnippetArrow())
				messageBuilder.WriteString(snippetLine)
			}
		}
	}

	logger.Info(messageBuilder.String())
}

// formatFingerprintMatches 格式化指纹匹配结果 (Cli版本)
func (sc *ScanController) formatFingerprintMatches(matches []*interfaces.FingerprintMatch, showRule bool) string {
	if len(matches) == 0 {
		return ""
	}

	var parts []string
	for _, match := range matches {
		if match == nil {
			continue
		}

		display := formatter.FormatFingerprintDisplay(match.RuleName, match.Matcher, showRule)
		if display != "" {
			parts = append(parts, display)
		}
	}

	return strings.Join(parts, " ")
}
