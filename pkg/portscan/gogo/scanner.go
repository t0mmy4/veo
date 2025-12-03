package gogo

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"veo/pkg/portscan"
	"veo/pkg/utils/logger"
)

// DefaultRate 默认扫描速率
const DefaultRate = 1000

// DefaultTimeout 默认超时时间
const DefaultTimeout = 3 * time.Second

// DefaultRetry 默认重试次数
const DefaultRetry = 0

// Scanner 端口扫描器
type Scanner struct {
	Rate    int
	Timeout time.Duration
	Threads int
	Retry   int
}

// Option 扫描器配置选项
type Option func(*Scanner)

// WithRate 设置扫描速率
func WithRate(rate int) Option {
	return func(s *Scanner) {
		if rate > 0 {
			s.Rate = rate
		}
	}
}

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		if timeout > 0 {
			s.Timeout = timeout
		}
	}
}

// WithThreads 设置并发线程数
func WithThreads(threads int) Option {
	return func(s *Scanner) {
		if threads > 0 {
			s.Threads = threads
		}
	}
}

// WithRetry 设置重试次数
func WithRetry(retry int) Option {
	return func(s *Scanner) {
		if retry >= 0 {
			s.Retry = retry
		}
	}
}

// NewScanner 创建新的扫描器实例
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{
		Rate:    DefaultRate,
		Timeout: DefaultTimeout,
		Retry:   DefaultRetry,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Scan 执行同步端口扫描
func (s *Scanner) Scan(ctx context.Context, targets []string, portsExpr string) ([]portscan.OpenPortResult, error) {
	// 1. 解析目标IP
	ips, err := portscan.ResolveTargetsToIPs(targets)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("未找到有效目标IP")
	}

	// 2. 解析端口
	ports, err := portscan.ParsePortExpression(portsExpr)
	if err != nil {
		return nil, fmt.Errorf("解析端口失败: %v", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("未找到有效端口")
	}

	logger.Infof("开始端口扫描，目标数: %d，端口数: %d，速率: %d", len(ips), len(ports), s.Rate)

	// 3. 执行扫描
	return s.scanCore(ctx, ips, ports)
}

// ScanStream 执行流式端口扫描
func (s *Scanner) ScanStream(ctx context.Context, targets []string, portsExpr string) (<-chan portscan.OpenPortResult, error) {
	// 1. 解析目标IP
	ips, err := portscan.ResolveTargetsToIPs(targets)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("未找到有效目标IP")
	}

	// 2. 解析端口
	ports, err := portscan.ParsePortExpression(portsExpr)
	if err != nil {
		return nil, fmt.Errorf("解析端口失败: %v", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("未找到有效端口")
	}

	logger.Infof("开始流式端口扫描，目标数: %d，端口数: %d，速率: %d", len(ips), len(ports), s.Rate)

	out := make(chan portscan.OpenPortResult, 100) // Buffer a bit
	go func() {
		defer close(out)
		s.scanCoreStream(ctx, ips, ports, out)
	}()

	return out, nil
}

// scanCore 执行扫描核心逻辑 (同步)
func (s *Scanner) scanCore(ctx context.Context, ips []string, ports []int) ([]portscan.OpenPortResult, error) {
	var results []portscan.OpenPortResult
	var mutex sync.Mutex

	out := make(chan portscan.OpenPortResult, 100)
	done := make(chan struct{})

	// 收集结果
	go func() {
		defer close(done)
		for r := range out {
			mutex.Lock()
			results = append(results, r)
			mutex.Unlock()
		}
	}()

	s.scanCoreStream(ctx, ips, ports, out)
	// scanCoreStream closes internal channels but we passed 'out'.
	// scanCoreStream does NOT close 'out'. We must close it here after scanCoreStream returns.
	close(out)
	<-done

	return deduplicateResults(results), nil
}

// scanCoreStream 执行扫描核心逻辑 (流式)
func (s *Scanner) scanCoreStream(ctx context.Context, ips []string, ports []int, out chan<- portscan.OpenPortResult) {
	// 任务通道
	totalTasks := int64(len(ips) * len(ports))
	taskCh := make(chan task, s.Rate)
	var wg sync.WaitGroup

	// 并发控制
	concurrency := s.Threads
	if concurrency <= 0 {
		// 动态调整并发数：基于速率和超时时间估算
		// 假设平均每个连接耗时 Timeout/2 (保守估计)
		// 实际上 Connect Scan 很快，但在防火墙丢包时会很慢
		// 限制最大并发数以防 fd 耗尽
		concurrency = s.Rate
		if concurrency < 100 {
			concurrency = 100
		}
		if concurrency > 3000 {
			concurrency = 3000
		}
	}

	// 速率限制器 (使用改进的批量令牌桶)
	limiter := newBatchRateLimiter(s.Rate)
	defer limiter.Stop()

	// 进度统计
	var progress int64
	progressDone := make(chan struct{})
	go s.printProgress(totalTasks, &progress, progressDone)

	// 启动Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskCh {
				// 检查上下文取消
				select {
				case <-ctx.Done():
					return
				default:
				}

				// 等待令牌
				limiter.Wait()

				if s.checkPort(t.ip, t.port) {
					result := portscan.OpenPortResult{
						IP:   t.ip,
						Port: t.port,
					}
					select {
					case out <- result:
					case <-ctx.Done():
						return
					}
				}
				atomic.AddInt64(&progress, 1)
			}
		}()
	}

	// 生成任务
	go func() {
		defer close(taskCh)
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case taskCh <- task{ip: ip, port: port}:
				}
			}
		}
	}()

	wg.Wait()
	close(progressDone)
}

type task struct {
	ip   string
	port int
}

// checkPort 检查端口是否开放 (Connect Scan)
func (s *Scanner) checkPort(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	// 智能重试机制：只在 Timeout 时重试
	for i := 0; i <= s.Retry; i++ {
		d := net.Dialer{Timeout: s.Timeout}
		conn, err := d.Dial("tcp", address)
		if err == nil {
			conn.Close()
			return true
		}

		// 错误分析
		// 1. 显式拒绝 (Connection Refused): 端口关闭，无需重试
		if strings.Contains(err.Error(), "connection refused") {
			return false
		}

		// 2. 检查是否为超时
		isTimeout := false
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			isTimeout = true
		}

		// 3. 如果不是超时错误（例如 network unreachable, no route to host），通常也不需要重试
		if !isTimeout {
			// 记录非超时错误供调试
			if i == 0 {
				logger.Debugf("端口连接失败(非超时) %s:%d: %v", ip, port, err)
			}
			return false
		}

		// 4. 是超时错误，继续重试
		if i == s.Retry {
			// 最后一次重试仍超时，记录日志
			logger.Debugf("端口连接超时(已重试%d次) %s:%d", s.Retry, ip, port)
		}
	}
	return false
}

func (s *Scanner) printProgress(total int64, current *int64, done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			// 打印最终进度
			curr := atomic.LoadInt64(current)
			if total > 0 {
				fmt.Printf("\rPortScan Progress: %.2f%% (%d/%d)\n", float64(curr)/float64(total)*100, curr, total)
			}
			return
		case <-ticker.C:
			curr := atomic.LoadInt64(current)
			if total > 0 {
				fmt.Printf("\rPortScan Progress: %.2f%% (%d/%d)", float64(curr)/float64(total)*100, curr, total)
			}
		}
	}
}

// batchRateLimiter 批量令牌桶速率限制器
// 相比简单的 Ticker，它能更好地处理高并发下的微小间隔问题，减少 CPU 上下文切换
type batchRateLimiter struct {
	ticker *time.Ticker
	ch     chan struct{}
	done   chan struct{}
}

func newBatchRateLimiter(rate int) *batchRateLimiter {
	// 目标更新间隔：20ms (50Hz)，避免过于频繁的 Ticker 触发
	interval := 20 * time.Millisecond
	// 计算每个间隔应投放的令牌数
	tokensPerInterval := int(float64(rate) * float64(interval) / float64(time.Second))

	// 如果速率很低（< 50/s），回退到简单的 Ticker 模式
	if tokensPerInterval < 1 {
		interval = time.Second / time.Duration(rate)
		tokensPerInterval = 1
	}

	l := &batchRateLimiter{
		ticker: time.NewTicker(interval),
		// 缓冲区大小设为每次投放量的2倍，允许一定的突发
		ch:   make(chan struct{}, tokensPerInterval*2),
		done: make(chan struct{}),
	}

	go func() {
		for {
			select {
			case <-l.done:
				return
			case <-l.ticker.C:
				// 投放令牌
				for i := 0; i < tokensPerInterval; i++ {
					select {
					case l.ch <- struct{}{}:
					default:
						// 桶满了，丢弃令牌（限制最大积压/突发）
					}
				}
			}
		}
	}()
	return l
}

func (l *batchRateLimiter) Wait() {
	<-l.ch
}

func (l *batchRateLimiter) Stop() {
	l.ticker.Stop()
	close(l.done)
}

func deduplicateResults(results []portscan.OpenPortResult) []portscan.OpenPortResult {
	unique := make(map[string]struct{})
	var clean []portscan.OpenPortResult
	for _, r := range results {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if _, exists := unique[key]; !exists {
			unique[key] = struct{}{}
			clean = append(clean, r)
		}
	}
	return clean
}
