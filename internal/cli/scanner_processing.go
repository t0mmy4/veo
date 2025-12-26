package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	sharedutils "veo/pkg/utils/shared"
)

func (sc *ScanController) applyFilterForTarget(responses []*interfaces.HTTPResponse, target string, externalFilter *dirscan.ResponseFilter) (*interfaces.FilterResult, error) {
	logger.Debugf("开始对目标 %s 应用过滤器，响应数量: %d (外部过滤器: %v)", target, len(responses), externalFilter != nil)

	var responseFilter *dirscan.ResponseFilter

	if externalFilter != nil {
		// 使用传入的外部过滤器（通常用于递归扫描共享状态）
		responseFilter = externalFilter
		logger.Debugf("使用外部传入的过滤器")
	} else {
		// 非递归模式（初始扫描）：使用站点级别缓存
		targetKey := sc.extractBaseURL(target)

		sc.siteFiltersMu.Lock()
		var exists bool
		responseFilter, exists = sc.siteFilters[targetKey]
		if !exists {
			responseFilter = dirscan.CreateResponseFilterFromExternal()

			if sc.fingerprintEngine != nil {
				responseFilter.SetFingerprintEngine(sc.fingerprintEngine)
				logger.Debugf("目录扫描模块已启用指纹二次识别功能，引擎类型: %T", sc.fingerprintEngine)

				// [取消] 二次指纹识别无需主动探测（icon和404）
				// 仅保留被动页面识别，避免重复发包
				// responseFilter.SetHTTPClient(sc.requestProcessor)
			} else {
				logger.Debugf("指纹引擎为nil，未启用二次识别")
			}

			sc.siteFilters[targetKey] = responseFilter
			logger.Debugf("为站点 %s 创建新的过滤器", targetKey)
		} else {
			logger.Debugf("复用站点 %s 的过滤器状态", targetKey)
		}
		sc.siteFiltersMu.Unlock()
	}

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)
	logger.Debugf("过滤器返回 - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
		len(filterResult.ValidPages), len(filterResult.PrimaryFilteredPages), len(filterResult.StatusFilteredPages))

	// [去重] 全局结果去重，只显示未显示过的URL
	sc.displayedURLsMu.Lock()
	var uniqueValidPages []*interfaces.HTTPResponse
	for _, page := range filterResult.ValidPages {
		if !sc.displayedURLs[page.URL] {
			sc.displayedURLs[page.URL] = true
			uniqueValidPages = append(uniqueValidPages, page)
		}
	}
	filterResult.ValidPages = uniqueValidPages
	sc.displayedURLsMu.Unlock()

	// 显示单个目标的过滤结果（现在会包含指纹信息）
	logger.Debugf("目标 %s 过滤完成:", target)
	// [重构] 打印逻辑移出，这里不再直接打印，但为了调试信息，可以保留简单的 count 输出
	// responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("目标 %s 过滤完成 - 原始响应: %d, 有效结果: %d",
		target, len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

// processTargetResponses 处理目标响应：类型转换、应用过滤器、收集统计
func (sc *ScanController) processTargetResponses(ctx context.Context, responses []*interfaces.HTTPResponse, target string, filter *dirscan.ResponseFilter) ([]*interfaces.HTTPResponse, error) {
	if len(responses) == 0 {
		return nil, nil
	}

	// 应用过滤器 (直接使用指针切片)
	filterResult, err := sc.applyFilterForTarget(responses, target, filter)
	if err != nil {
		logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
		// 如果过滤失败，返回原始结果（Fail Open）
		return responses, err
	}

	// 收集被过滤的页面用于报告
	sc.collectedResultsMu.Lock()
	sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, toValueSlice(filterResult.PrimaryFilteredPages)...)
	sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, toValueSlice(filterResult.StatusFilteredPages)...)
	sc.collectedResultsMu.Unlock()

	// 返回有效结果
	// 注意：之前这里直接返回 ValidPages，但调用方 (如 passive scan) 可能期望 []interfaces.HTTPResponse
	// 但 processTargetResponses 签名已改为返回 []*interfaces.HTTPResponse，所以直接返回
	return filterResult.ValidPages, nil
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	var matches []types.FingerprintMatch
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, sc.showFingerprintSnippet)
		}
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		fingerprintPages = toValueSlice(filterResult.ValidPages)
	}

	return report.GenerateCombinedJSON(dirPages, fingerprintPages, matches)
}

func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（interfaces.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// 关键修复：处理响应体解压缩和编码转换
	processedBody := sc.processResponseBody(resp)

	// 提取处理后的标题（使用解压缩和编码转换后的内容）
	title := sc.extractTitleFromHTML(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET", // 主动扫描默认使用GET方法
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody, // 使用处理后的响应体
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)), // 更新为处理后的长度
		Server:          resp.Server,
		Title:           title, // 使用处理后的标题
	}
}

func (sc *ScanController) processResponseBody(resp *interfaces.HTTPResponse) string {
	if resp == nil || resp.ResponseBody == "" {
		return ""
	}

	rawBody := resp.ResponseBody

	// 步骤1: 检查Content-Encoding并解压缩
	decompressedBody := sc.decompressResponseBody(rawBody, resp.ResponseHeaders)

	// 步骤2: 字符编码检测和转换
	convertedBody := fingerprint.GetEncodingDetector().DetectAndConvert(decompressedBody, resp.ContentType)

	logger.Debugf("响应体处理: %s (原始: %d -> 解压: %d -> 转换: %d bytes)",
		resp.URL, len(rawBody), len(decompressedBody), len(convertedBody))

	return convertedBody
}

func (sc *ScanController) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if headers != nil {
		if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
			contentEncoding = encodingHeaders[0]
		}
	}

	decompressed := sharedutils.DecompressByEncoding([]byte(body), contentEncoding)
	return string(decompressed)
}

func (sc *ScanController) extractTitleFromHTML(body string) string {
	return sharedutils.ExtractTitle(body)
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractBaseURLWithPath 从完整URL中提取基础URL（协议+主机+路径），去除查询参数和片段
func (sc *ScanController) extractBaseURLWithPath(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		path := parsedURL.Path
		// 移除末尾的斜杠，保证一致性，除非路径就是根目录
		if path != "/" {
			path = strings.TrimRight(path, "/")
		}
		if path == "" {
			path = "/" // 理论上Parse不会返回空path如果只是host，但为了保险
		}
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, path)
	}
	return rawURL
}
