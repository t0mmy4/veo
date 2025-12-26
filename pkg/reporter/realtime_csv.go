package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"veo/pkg/utils/interfaces"
)

type RealtimeCSVReporter struct {
	mu     sync.Mutex
	file   *os.File
	writer *csv.Writer
	path   string
	closed bool
}

func NewRealtimeCSVReporter(outputPath string) (*RealtimeCSVReporter, error) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return nil, fmt.Errorf("输出路径为空")
	}

	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	realtimePath := base + "_realtime.csv"

	if err := os.MkdirAll(filepath.Dir(realtimePath), 0o755); err != nil {
		return nil, fmt.Errorf("创建输出目录失败: %w", err)
	}

	f, err := os.OpenFile(realtimePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("打开输出文件失败: %w", err)
	}

	r := &RealtimeCSVReporter{
		file:   f,
		writer: csv.NewWriter(f),
		path:   realtimePath,
	}

	if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
		if err := r.writer.Write([]string{"URL", "StatusCode", "Title", "Fingerprint"}); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("写入CSV表头失败: %w", err)
		}
		r.writer.Flush()
		if werr := r.writer.Error(); werr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("写入CSV表头失败: %w", werr)
		}
	}

	return r, nil
}

func (r *RealtimeCSVReporter) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

func (r *RealtimeCSVReporter) WriteResponse(resp *interfaces.HTTPResponse) error {
	if r == nil || resp == nil {
		return nil
	}

	fingerprints := make([]string, 0, len(resp.Fingerprints))
	for _, fp := range resp.Fingerprints {
		if fp.RuleName != "" {
			fingerprints = append(fingerprints, fp.RuleName)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("realtime csv reporter 已关闭")
	}

	if err := r.writer.Write([]string{
		resp.URL,
		strconv.Itoa(resp.StatusCode),
		resp.Title,
		strings.Join(fingerprints, "|"),
	}); err != nil {
		return err
	}

	r.writer.Flush()
	if err := r.writer.Error(); err != nil {
		return err
	}

	return nil
}

func (r *RealtimeCSVReporter) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	// Flush csv.Writer
	r.writer.Flush()
	werr := r.writer.Error()

	// 尽量确保落盘（不在每条记录Sync，避免性能劣化）
	syncErr := r.file.Sync()
	closeErr := r.file.Close()

	if werr != nil {
		return werr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// GenerateRealtimeCSVReport 生成实时CSV报告（与实时输出格式一致）
func GenerateRealtimeCSVReport(filterResult *interfaces.FilterResult, outputPath string) (string, error) {
	if filterResult == nil {
		return "", fmt.Errorf("过滤结果为空")
	}

	reporter, err := NewRealtimeCSVReporter(outputPath)
	if err != nil {
		return "", err
	}

	for _, page := range filterResult.ValidPages {
		if page == nil {
			continue
		}
		if err := reporter.WriteResponse(page); err != nil {
			_ = reporter.Close()
			return "", err
		}
	}

	if err := reporter.Close(); err != nil {
		return "", err
	}

	return reporter.Path(), nil
}
