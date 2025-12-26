package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"veo/internal/scheduler"
	"veo/pkg/dirscan"
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

	// 执行递归扫描
	var allResults []interfaces.HTTPResponse
	var recursiveFilter *dirscan.ResponseFilter = nil
	maxDepth := sc.args.Depth

	allResults, _ = dirscan.RunRecursiveScan(
		ctx,
		targets,
		maxDepth,
		layerScanner,
		recursiveFilter,
	)

	return allResults, nil
}

func (sc *ScanController) runConcurrentDirscan(ctx context.Context, targets []string, filter *dirscan.ResponseFilter, recursive bool) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("目标数量: %d", len(targets))

	// [新增] 实时结果处理回调
	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex

	// 启动独立的打印协程
	printChan := make(chan *interfaces.HTTPResponse, 100)
	printWg := sync.WaitGroup{}
	printWg.Add(1)
	go sc.startResultPrinter(printChan, &printWg)

	// 创建目标调度器（直接传入所有参数）
	scheduler := scheduler.NewTargetScheduler(
		ctx,
		targets,
		sc.requestProcessor,
		recursive,
		sc.requestProcessor.GetConfig().Timeout,
		func(target string, resp *interfaces.HTTPResponse) {
			sc.handleRealTimeResult(ctx, target, resp, filter, &allResults, &resultsMu, printChan)
		},
	)

	// 执行并发扫描（callback-only：结果通过回调实时处理）
	err := scheduler.ExecuteConcurrentScan()

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
	go sc.startResultPrinter(printChan, &printWg)

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

		// 发起HTTP请求（实时处理）
		// 使用支持 ctx 的版本，确保 Ctrl+C 能尽快停止当前目标的剩余URL派发
		sc.requestProcessor.ProcessURLsWithCallbackOnlyWithContext(ctx, scanURLs, func(resp *interfaces.HTTPResponse) {
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

	fullPath := parsedURL.Path
	if parsedURL.Fragment != "" {
		fullPath = fullPath + "#" + parsedURL.Fragment
	}

	path := strings.Trim(fullPath, "/")
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
		lastTarget := scanTargets[len(scanTargets)-1]
		return sc.urlGenerator.GenerateRecursiveURLs([]string{lastTarget})
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
			*results = append(*results, *page)

			// 写入实时CSV报告
			if sc.realtimeReporter != nil {
				_ = sc.realtimeReporter.WriteResponse(page)
			}

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
func (sc *ScanController) startResultPrinter(printChan <-chan *interfaces.HTTPResponse, wg *sync.WaitGroup) {
	defer wg.Done()

	for page := range printChan {
		if page == nil {
			continue
		}
		printHTTPResponseResult(page, sc.showFingerprintSnippet, sc.args.Verbose || sc.args.VeryVerbose)
	}
}
