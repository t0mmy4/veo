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
		responses := sc.requestProcessor.ProcessURLs(urls)
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

	scheduler.SetResultCallback(func(target string, resp *interfaces.HTTPResponse) {
		sc.handleRealTimeResult(ctx, target, resp, filter, &allResults, &resultsMu)
	})

	// 执行并发扫描
	// 注意：虽然 ExecuteConcurrentScan 返回所有原始结果，但我们已经在回调中处理了有效结果
	_, err := scheduler.ExecuteConcurrentScan()
	if err != nil {
		return nil, fmt.Errorf("多目标并发扫描失败: %v", err)
	}

	return allResults, nil
}

func (sc *ScanController) runSequentialDirscan(ctx context.Context, targets []string, filter *dirscan.ResponseFilter, recursive bool) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

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
		// 使用 ProcessURLsWithCallback 替代 ProcessURLs
		sc.requestProcessor.ProcessURLsWithCallback(scanURLs, func(resp *interfaces.HTTPResponse) {
			sc.handleRealTimeResult(ctx, target, resp, filter, &allResults, nil)
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
func (sc *ScanController) handleRealTimeResult(ctx context.Context, target string, resp *interfaces.HTTPResponse, filter *dirscan.ResponseFilter, results *[]interfaces.HTTPResponse, mu *sync.Mutex) {
	if resp == nil {
		return
	}
	// 调用 processTargetResponses 处理单个响应（包含过滤、去重、打印）
	validPages, _ := sc.processTargetResponses(ctx, []*interfaces.HTTPResponse{resp}, target, filter)

	if len(validPages) > 0 {
		if mu != nil {
			mu.Lock()
		}
		*results = append(*results, validPages...)
		if mu != nil {
			mu.Unlock()
		}
	}
}
