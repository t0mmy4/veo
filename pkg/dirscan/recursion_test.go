package dirscan

import (
	"context"
	"strings"
	"testing"
	"veo/pkg/utils/interfaces"
)

// Mock LayerScanner
// 模拟每一层的扫描行为
func mockLayerScanner(targets []string, filter *ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
	var results []interfaces.HTTPResponse
	for _, t := range targets {
		// 基础响应（当前目标有效）
		results = append(results, interfaces.HTTPResponse{
			URL:        t,
			StatusCode: 200,
		})

		// 模拟递归发现：如果目标是 /admin/，则发现子目录 /admin/users/
		if strings.HasSuffix(t, "/admin/") {
			child := t + "users/"
			results = append(results, interfaces.HTTPResponse{
				URL:        child,
				StatusCode: 200, // 200 状态码会被提取为下一层目标
			})
		}
	}
	return results, nil
}

func TestRunRecursiveScan(t *testing.T) {
	initialTargets := []string{"http://example.com/admin/"}
	maxDepth := 2 // 测试两层递归

	results, err := RunRecursiveScan(context.Background(), initialTargets, maxDepth, mockLayerScanner, nil)
	if err != nil {
		t.Fatalf("RunRecursiveScan failed: %v", err)
	}

	// 预期结果：
	// Depth 0: 扫描 /admin/ -> 发现 /admin/users/
	// Depth 1: 扫描 /admin/users/ -> 发现 nothing (mocks doesn't define deeper)
	// 结果集应包含 /admin/ 和 /admin/users/

	targetMap := make(map[string]bool)
	for _, r := range results {
		targetMap[r.URL] = true
	}

	expected := []string{
		"http://example.com/admin/",
		"http://example.com/admin/users/",
	}

	for _, exp := range expected {
		if !targetMap[exp] {
			t.Errorf("Expected URL not found: %s", exp)
		}
	}
}
