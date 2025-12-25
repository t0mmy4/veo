package cli

import (
	"strings"

	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// printHTTPResponseResult 打印单个有效HTTP响应（主动+被动通用）
func printHTTPResponseResult(page *interfaces.HTTPResponse, showSnippet bool, showRule bool) {
	if page == nil {
		return
	}

	// 使用已经识别好的指纹信息
	matches := page.Fingerprints
	var fingerprintUnion string

	// 格式化指纹显示
	if len(matches) > 0 {
		fingerprintUnion = formatFingerprintMatchesList(matches, showRule)
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

	if showSnippet && len(matches) > 0 {
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

// formatFingerprintMatchesList 格式化指纹匹配结果
func formatFingerprintMatchesList(matches []interfaces.FingerprintMatch, showRule bool) string {
	if len(matches) == 0 {
		return ""
	}

	parts := make([]string, 0, len(matches))
	for i := range matches {
		match := matches[i]
		display := formatter.FormatFingerprintDisplay(match.RuleName, match.Matcher, showRule)
		if display != "" {
			parts = append(parts, display)
		}
	}

	return strings.Join(parts, " ")
}
