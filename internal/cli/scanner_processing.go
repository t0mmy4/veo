package cli

import (
	"fmt"
	"net/url"
	"strings"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	sharedutils "veo/pkg/utils/shared"
)

func (sc *ScanController) generateJSONReport(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, true)
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	includeSnippet := sc.showFingerprintSnippet
	if sc.args != nil && sc.args.JSONOutput {
		includeSnippet = true
	}
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, includeSnippet)
}

func (sc *ScanController) generateJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, includeSnippet bool) (string, error) {
	var matches []types.FingerprintMatch
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, includeSnippet)
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

	// 处理响应体解压缩和编码转换
	processedBody := ""
	if resp.ResponseBody != "" {
		if resp.BodyDecoded {
			processedBody = resp.ResponseBody
		} else {
			rawBody := resp.ResponseBody

			// Content-Encoding 解压
			var contentEncoding string
			if headers != nil {
				if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
					contentEncoding = encodingHeaders[0]
				}
			}

			decompressed := sharedutils.DecompressByEncoding([]byte(rawBody), contentEncoding)
			processedBody = fingerprint.GetEncodingDetector().DetectAndConvert(string(decompressed), resp.ContentType)
		}
	}

	// 提取处理后的标题
	title := sharedutils.ExtractTitle(processedBody)

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
