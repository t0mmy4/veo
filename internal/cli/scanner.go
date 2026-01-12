package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"veo/internal/core/config"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/fingerprint"
	reporter "veo/pkg/reporter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/stats"
)

func isJSONReportPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(path)), ".json")
}

// toValueSlice 将指针切片转换为值切片
func toValueSlice(pages []*interfaces.HTTPResponse) []interfaces.HTTPResponse {
	result := make([]interfaces.HTTPResponse, 0, len(pages))
	for _, p := range pages {
		if p != nil {
			result = append(result, *p)
		}
	}
	return result
}

// ScanController 扫描控制器
type ScanController struct {
	args                   *CLIArgs
	config                 *config.Config
	requestProcessor       *requests.RequestProcessor
	fingerprintEngine      *fingerprint.Engine
	probedHosts            map[string]bool
	probedMutex            sync.RWMutex
	statsDisplay           *stats.StatsDisplay
	showFingerprintSnippet bool
	reportPath             string
	wordlistPath           string
	realtimeReporter       *reporter.RealtimeCSVReporter

	lastDirscanResults     []interfaces.HTTPResponse
	lastFingerprintResults []interfaces.HTTPResponse

	displayedURLs   map[string]bool
	displayedURLsMu sync.Mutex

	collectedPrimaryFiltered []interfaces.HTTPResponse
	collectedStatusFiltered  []interfaces.HTTPResponse
	collectedResultsMu       sync.Mutex
}

func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	threads := args.Threads
	if threads <= 0 {
		threads = 100
	}
	retry := 1
	if args.RetrySet {
		retry = args.Retry
	}
	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 3
	}
	requestConfig := &requests.RequestConfig{
		Timeout:            time.Duration(timeout) * time.Second,
		MaxRetries:         retry,
		MaxConcurrent:      threads,
		RandomUserAgent:    args.RandomUA,
		DecompressResponse: true,
	}
	requests.ApplyRedirectPolicy(requestConfig)

	proxyURL := strings.TrimSpace(args.Proxy)
	if proxyURL == "" {
		if proxyCfg := config.GetProxyConfig(); proxyCfg != nil {
			proxyURL = strings.TrimSpace(proxyCfg.UpstreamProxy)
		}
	}
	if proxyURL != "" {
		requestConfig.ProxyURL = proxyURL
		logger.Debugf("ActiveScan: 设置请求处理器代理: %s", requestConfig.ProxyURL)
	}

	if !args.CheckSimilarOnly {
		logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
		logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
		logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)
	}

	var fpEngine *fingerprint.Engine
	if !args.CheckSimilarOnly && (args.HasModule(string(modulepkg.ModuleFinger)) || args.HasModule(string(modulepkg.ModuleDirscan))) {
		fpEngine = fingerprint.NewEngine(nil)
		if fpEngine != nil {
			if err := fpEngine.LoadRules(fpEngine.GetConfig().RulesPath); err != nil {
				logger.Warnf("加载指纹规则失败，指纹识别可能无结果: %v", err)
			}
		}
	}

	requestProcessor := requests.NewRequestProcessor(requestConfig)

	if len(args.Modules) == 1 && args.Modules[0] == "finger" {
		requestProcessor.SetModuleContext("fingerprint")
	}
	customHeaders := config.GetCustomHeaders()
	if len(customHeaders) > 0 {
		requestProcessor.SetCustomHeaders(customHeaders)
	}
	if args.Shiro {
		requestProcessor.SetShiroCookieEnabled(true)
	}

	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
	}

	if args.Stats {
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	snippetEnabled := args.VeryVerbose
	ruleEnabled := args.Verbose || args.VeryVerbose

	if fpEngine != nil {
		// 启用snippet捕获(用于报告)
		fpEngine.GetConfig().ShowSnippet = true

		// 创建OutputFormatter并注入到Engine
		var outputFormatter fingerprint.OutputFormatter
		if args.JSONOutput {
			jsonFormatter := fingerprint.NewJSONOutputFormatter()
			jsonFormatter.SetSuppressOutput(true)
			outputFormatter = jsonFormatter
		} else {
			consoleFormatter := fingerprint.NewConsoleOutputFormatter(
				true,           // logMatches
				true,           // showSnippet - 始终捕获
				ruleEnabled,    // showRules
				snippetEnabled, // consoleSnippetEnabled
			)
			outputFormatter = consoleFormatter
		}
		fpEngine.GetConfig().OutputFormatter = outputFormatter
		logger.Debugf("指纹引擎 OutputFormatter 已注入: %T", outputFormatter)
	}

	sc := &ScanController{
		args:                   args,
		config:                 cfg,
		requestProcessor:       requestProcessor,
		fingerprintEngine:      fpEngine,
		probedHosts:            make(map[string]bool),
		statsDisplay:           statsDisplay,
		showFingerprintSnippet: snippetEnabled,
		reportPath:             strings.TrimSpace(args.Output),
		wordlistPath:           strings.TrimSpace(args.Wordlist),
		displayedURLs:          make(map[string]bool),
	}

	return sc
}

func (sc *ScanController) Run() error {
	if strings.TrimSpace(sc.reportPath) != "" && !isJSONReportPath(sc.reportPath) {
		realtimeReporter, err := reporter.NewRealtimeCSVReporter(sc.reportPath)
		if err != nil {
			logger.Warnf("无法创建实时CSV报告: %v", err)
		} else {
			sc.realtimeReporter = realtimeReporter
			sc.attachRealtimeReporter()
			logger.Infof("Realtime CSV Report: %s", realtimeReporter.Path())
			defer func() {
				if err := realtimeReporter.Close(); err != nil {
					logger.Warnf("关闭实时CSV报告失败: %v", err)
				}
			}()
		}
	}

	return sc.runActiveMode()
}

func (sc *ScanController) attachRealtimeReporter() {
	if sc.realtimeReporter == nil || sc.fingerprintEngine == nil {
		return
	}

	hook := func(resp *fingerprint.HTTPResponse, matches []*fingerprint.FingerprintMatch, tags []string) {
		if resp == nil {
			return
		}
		page := *resp
		if len(matches) > 0 {
			page.Fingerprints = convertFingerprintMatches(matches, false)
		} else {
			page.Fingerprints = nil
		}
		_ = sc.realtimeReporter.WriteResponse(&page)
	}

	formatter := sc.fingerprintEngine.GetConfig().OutputFormatter
	switch f := formatter.(type) {
	case *fingerprint.ConsoleOutputFormatter:
		f.SetOutputHook(hook)
	case *fingerprint.JSONOutputFormatter:
		f.SetOutputHook(hook)
	}
}

func (sc *ScanController) runActiveMode() error {
	if sc.args == nil || !sc.args.CheckSimilarOnly {
		logger.Debug("启动主动扫描模式")
	}
	originalNetworkCheck := false
	if sc.args != nil {
		originalNetworkCheck = sc.args.NetworkCheck
		if sc.args.CheckSimilar && !sc.args.CheckSimilarOnly {
			sc.args.NetworkCheck = false
		}
	}

	targets, err := sc.parseTargets(sc.args.Targets)
	if sc.args != nil {
		sc.args.NetworkCheck = originalNetworkCheck
	}
	if err != nil {
		return fmt.Errorf("Target Parse Error: %v", err)
	}

	logger.Debugf("解析到 %d 个目标", len(targets))

	orderedModules := sc.getOptimizedModuleOrder()

	// 信号处理：捕获 Ctrl+C / SIGTERM，通过 ctx 取消让各模块尽快收敛
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	defer close(done)

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		interruptCount := 0
		for {
			select {
			case <-sigChan:
				interruptCount++
				if interruptCount == 1 {
					cancel()
					go func() {
						select {
						case <-done:
							return
						case <-time.After(3 * time.Second):
							os.Exit(1)
						}
					}()
				} else {
					os.Exit(1)
				}
			case <-done:
				return
			}
		}
	}()

	if sc.args.CheckSimilarOnly {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
		for _, target := range targets {
			fmt.Println(target)
		}
		return nil
	}

	if sc.args.CheckSimilar {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
	}

	// 打印有效性筛选结果
	if !sc.args.JSONOutput {
		logger.Infof("Available Hosts: %d", len(targets))
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	// 同步执行：避免 goroutine 写结果、主流程读结果带来的数据竞争
	allResults, dirscanResults, fingerprintResults := sc.executeModulesSequenceWithContext(ctx, orderedModules, targets)

	return sc.finalizeScan(allResults, dirscanResults, fingerprintResults)
}

func (sc *ScanController) executeModulesSequenceWithContext(ctx context.Context, modules []string, targets []string) ([]interfaces.HTTPResponse, []interfaces.HTTPResponse, []interfaces.HTTPResponse) {
	var allResults []interfaces.HTTPResponse
	var dirResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	if len(modules) == 0 || len(targets) == 0 {
		return allResults, dirResults, fingerprintResults
	}

	for i, moduleName := range modules {
		// 检查Context是否取消
		select {
		case <-ctx.Done():
			return allResults, dirResults, fingerprintResults
		default:
		}

		logger.Debugf("开始执行模块: %s (%d/%d)", moduleName, i+1, len(modules))

		moduleResults, err := sc.runModuleForTargetsWithContext(ctx, moduleName, targets)
		if err != nil {
			logger.Errorf("模块 %s 执行失败: %v", moduleName, err)
			continue
		}

		allResults = append(allResults, moduleResults...)
		switch moduleName {
		case string(modulepkg.ModuleDirscan):
			dirResults = append(dirResults, moduleResults...)
		case string(modulepkg.ModuleFinger):
			fingerprintResults = append(fingerprintResults, moduleResults...)
		}
		logger.Debugf("模块 %s 完成，获得 %d 个结果", moduleName, len(moduleResults))

		if len(modules) > 1 && i < len(modules)-1 && !sc.args.JSONOutput {
			fmt.Println()
		}
	}

	return allResults, dirResults, fingerprintResults
}

func (sc *ScanController) finalizeScan(allResults, dirResults, fingerprintResults []interfaces.HTTPResponse) error {
	logger.Debugf("所有模块执行完成，总结果数: %d", len(allResults))

	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == string(modulepkg.ModuleFinger)
	var filterResult *interfaces.FilterResult

	if onlyFingerprint {
		pages := fingerprintResults
		if len(pages) == 0 {
			pages = allResults
		}
		// Convert value slice to pointer slice for FilterResult
		validPages := make([]*interfaces.HTTPResponse, len(pages))
		for i := range pages {
			validPages[i] = &pages[i]
		}

		filterResult = &interfaces.FilterResult{
			ValidPages: validPages,
		}
	} else {
		// Convert value slices to pointer slices
		validPages := make([]*interfaces.HTTPResponse, len(allResults))
		for i := range allResults {
			validPages[i] = &allResults[i]
		}

		primaryFiltered := make([]*interfaces.HTTPResponse, len(sc.collectedPrimaryFiltered))
		for i := range sc.collectedPrimaryFiltered {
			primaryFiltered[i] = &sc.collectedPrimaryFiltered[i]
		}

		statusFiltered := make([]*interfaces.HTTPResponse, len(sc.collectedStatusFiltered))
		for i := range sc.collectedStatusFiltered {
			statusFiltered[i] = &sc.collectedStatusFiltered[i]
		}

		filterResult = &interfaces.FilterResult{
			ValidPages:           validPages,
			PrimaryFilteredPages: primaryFiltered,
			StatusFilteredPages:  statusFiltered,
		}
		logger.Debugf("构造FilterResult - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
			len(allResults), len(sc.collectedPrimaryFiltered), len(sc.collectedStatusFiltered))
		if len(allResults) > 0 {
			logger.Debugf("所有目标过滤完成，最终有效结果: %d", len(allResults))
		}
	}

	sc.lastDirscanResults = dirResults
	sc.lastFingerprintResults = fingerprintResults

	if sc.realtimeReporter != nil {
		logger.Infof("Report Output Success: %s", sc.realtimeReporter.Path())
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.ShowFinalStats()
		sc.statsDisplay.Disable()
	}

	if sc.args.JSONOutput {
		jsonStr, err := sc.generateConsoleJSON(dirResults, fingerprintResults, filterResult)
		if err != nil {
			logger.Errorf("生成JSON输出失败: %v", err)
		} else {
			fmt.Println(jsonStr)
		}
	}

	if isJSONReportPath(sc.reportPath) {
		jsonStr, err := sc.generateJSONReport(dirResults, fingerprintResults, filterResult)
		if err != nil {
			logger.Errorf("生成JSON报告失败: %v", err)
		} else if writeErr := os.WriteFile(sc.reportPath, []byte(jsonStr), 0644); writeErr != nil {
			logger.Errorf("写入JSON报告失败: %v", writeErr)
		} else {
			logger.Infof("Report Output Success: %s", sc.reportPath)
		}
	}

	return nil
}

func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

	for _, module := range sc.args.Modules {
		if module == "finger" {
			orderedModules = append(orderedModules, module)
			break
		}
	}

	// 然后执行其他模块
	for _, module := range sc.args.Modules {
		if module != "finger" {
			orderedModules = append(orderedModules, module)
		}
	}

	return orderedModules
}

func (sc *ScanController) runModuleForTargetsWithContext(ctx context.Context, moduleName string, targets []string) ([]interfaces.HTTPResponse, error) {
	// 简单的包装，未来应该修改 runDirscanModule 和 runFingerprintModule 以接受 Context
	// 目前我们主要关注指纹识别模块的并发控制

	switch moduleName {
	case "dirscan":
		// 目录扫描集成 Context
		return sc.runDirscanModule(ctx, targets)
	case "finger":
		return sc.runFingerprintModuleWithContext(ctx, targets)

	default:
		return nil, fmt.Errorf("不支持的模块: %s", moduleName)
	}
}
