package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"veo/pkg/dirscan"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	processor "veo/pkg/utils/processor"
)

// TargetScheduler 目标调度器（多目标并发优化）
type TargetScheduler struct {
	targets                []string
	maxTargetWorkers       int
	urlConcurrentPerTarget int
	ctx                    context.Context
	baseRequestProcessor   *processor.RequestProcessor            // 基础请求处理器（支持统计更新）
	recursive              bool                                   // 是否递归模式
	resultCallback         func(string, *interfaces.HTTPResponse) // 结果回调
	requestTimeout         time.Duration                          // 单次请求超时时间
}

// NewTargetScheduler 创建目标调度器
func NewTargetScheduler(
	ctx context.Context,
	targets []string,
	baseProcessor *processor.RequestProcessor,
	recursive bool,
	requestTimeout time.Duration,
	callback func(string, *interfaces.HTTPResponse),
) *TargetScheduler {
	maxTargetWorkers, urlConcurrentPerTarget := calculateResourceAllocation(targets, baseProcessor)

	return &TargetScheduler{
		targets:                targets,
		maxTargetWorkers:       maxTargetWorkers,
		urlConcurrentPerTarget: urlConcurrentPerTarget,
		ctx:                    ctx,
		baseRequestProcessor:   baseProcessor,
		recursive:              recursive,
		requestTimeout:         requestTimeout,
		resultCallback:         callback,
	}
}

// ExecuteConcurrentScan 执行并发扫描（callback-only）
func (ts *TargetScheduler) ExecuteConcurrentScan() error {
	scanCtx := ts.ctx
	if ts.resultCallback == nil {
		return fmt.Errorf("result callback is nil")
	}
	if ts.baseRequestProcessor == nil {
		return fmt.Errorf("base request processor is nil")
	}

	var wg sync.WaitGroup
	// 创建目标工作器信号量
	targetSem := make(chan struct{}, ts.maxTargetWorkers)

	// 启动目标工作器
	for i, target := range ts.targets {
		wg.Add(1)
		go func(index int, targetURL string) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("目标处理panic恢复: %v, 目标: %s", r, targetURL)
				}
				wg.Done()
			}()

			// 阻塞等待信号量，除非扫描上下文被取消
			select {
			case targetSem <- struct{}{}:
				defer func() {
					<-targetSem
				}()
			case <-scanCtx.Done():
				logger.Debugf("目标 %s: 扫描被取消", targetURL)
				return
			}

			ts.processTarget(scanCtx, index, targetURL)
		}(i, target)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-scanCtx.Done():
		return scanCtx.Err()
	}
}

func (ts *TargetScheduler) processTarget(ctx context.Context, index int, target string) {
	startTime := time.Now()
	logger.Debugf("开始处理目标 [%d/%d]: %s", index+1, len(ts.targets), target)

	// 确定超时时间
	timeout := ts.requestTimeout
	if timeout <= 0 {
		if cfg := ts.baseRequestProcessor.GetConfig(); cfg != nil {
			timeout = cfg.Timeout
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	moduleCtx := fmt.Sprintf("target-%s", extractDomainFromURL(target))
	requestProcessor := ts.baseRequestProcessor.CloneWithContext(moduleCtx, timeout)
	requestConfig := requestProcessor.GetConfig()
	requestConfig.MaxConcurrent = ts.urlConcurrentPerTarget
	logger.Debugf("复用BaseRequestProcessor创建Worker: %s (并发限制: %d)", moduleCtx, ts.urlConcurrentPerTarget)

	select {
	case <-ctx.Done():
		logger.Debugf("目标 %s: 生成URL时被取消", target)
		return
	default:
	}

	// 生成扫描URL
	urlGenerator := dirscan.NewURLGenerator()
	var scanURLs []string
	if ts.recursive {
		scanURLs = urlGenerator.GenerateRecursiveURLs([]string{target})
	} else {
		scanURLs = urlGenerator.GenerateURLs([]string{target})
	}

	if len(scanURLs) == 0 {
		logger.Warnf("%s 未生成扫描URL", target)
		return
	}
	logger.Debugf("%s 生成了 %d 个扫描URL", target, len(scanURLs))

	select {
	case <-ctx.Done():
		logger.Debugf("目标 %s: 执行请求时被取消", target)
		return
	default:
	}

	// 执行请求
	timeoutDuration := time.Duration(len(scanURLs)) * time.Second
	if timeoutDuration < 5*time.Minute {
		timeoutDuration = 5 * time.Minute
	}
	if timeoutDuration > 24*time.Hour {
		timeoutDuration = 24 * time.Hour
	}

	requestCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("目标处理panic: %v, 目标: %s", r, target)
		}
	}()

	requestProcessor.ProcessURLsWithCallbackOnlyWithContext(requestCtx, scanURLs, func(resp *interfaces.HTTPResponse) {
		ts.resultCallback(target, resp)
	})

	statsUpdater := ts.baseRequestProcessor.GetStatsUpdater()
	if statsUpdater != nil {
		statsUpdater.IncrementCompletedHosts()
		logger.Debugf("目标 %s 完成，更新已完成主机数", target)
	}

	logger.Debugf("目标 %s 处理完成，耗时: %v", target, time.Since(startTime))
}

// calculateResourceAllocation 计算资源分配
func calculateResourceAllocation(targets []string, baseProcessor *processor.RequestProcessor) (int, int) {
	targetCount := len(targets)

	totalConcurrent := 0
	if baseProcessor != nil {
		if cfg := baseProcessor.GetConfig(); cfg != nil && cfg.MaxConcurrent > 0 {
			totalConcurrent = cfg.MaxConcurrent
		}
	}
	if totalConcurrent <= 0 {
		totalConcurrent = 50
	}

	// 单目标：全部资源分配给该目标
	if targetCount == 1 {
		return 1, totalConcurrent
	}

	// 计算最大目标并发数 (5-50之间)
	maxTargetConcurrent := totalConcurrent / 10
	if maxTargetConcurrent < 5 {
		maxTargetConcurrent = 5
	} else if maxTargetConcurrent > 50 {
		maxTargetConcurrent = 50
	}

	// 确定实际目标并发数和每目标URL并发数
	var actualTargetWorkers, urlConcurrentPerTarget int
	if targetCount <= maxTargetConcurrent {
		// 少量目标：平均分配
		actualTargetWorkers = targetCount
		urlConcurrentPerTarget = totalConcurrent / targetCount
	} else {
		// 大量目标：限制目标并发数
		actualTargetWorkers = maxTargetConcurrent
		urlConcurrentPerTarget = totalConcurrent / maxTargetConcurrent
	}

	// 保证每目标最少有一定请求并发
	if urlConcurrentPerTarget < 5 {
		urlConcurrentPerTarget = 5
	}

	return actualTargetWorkers, urlConcurrentPerTarget
}

// extractDomainFromURL 从URL中提取域名
func extractDomainFromURL(rawURL string) string {
	// 简单的域名提取，用于日志标识
	if len(rawURL) > 50 {
		return rawURL[:47] + "..."
	}
	return rawURL
}
