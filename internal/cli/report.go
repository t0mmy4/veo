package cli

import (
	"fmt"
	"strings"

	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ReportConfig 报告生成配置
type ReportConfig struct {
	Modules                []string
	OutputPath             string
	ShowFingerprintSnippet bool
}

// GenerateReport 生成报告（仅实时CSV）
func GenerateReport(config *ReportConfig, dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, fpEngine *fingerprint.Engine) error {
	reportPath := strings.TrimSpace(config.OutputPath)
	if reportPath == "" {
		logger.Debug("未指定输出路径，跳过报告生成")
		return nil
	}

	finalPath, err := report.GenerateRealtimeCSVReport(filterResult, reportPath)
	if err != nil {
		return fmt.Errorf("报告生成失败: %v", err)
	}

	logger.Infof("Report Output Success: %s", finalPath)
	return nil
}

func convertFingerprintMatches(matches []*fingerprint.FingerprintMatch, includeSnippet bool) []types.FingerprintMatch {
	if len(matches) == 0 {
		return nil
	}

	converted := make([]types.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}

		matcher := match.Matcher
		if matcher == "" {
			matcher = match.DSLMatched
		}
		dslMatched := match.DSLMatched
		if dslMatched == "" {
			dslMatched = matcher
		}
		convertedMatch := types.FingerprintMatch{
			URL:        match.URL,
			RuleName:   match.RuleName,
			Matcher:    matcher,
			DSLMatched: dslMatched,
			Timestamp:  match.Timestamp,
		}
		if includeSnippet {
			convertedMatch.Snippet = match.Snippet
		}
		converted = append(converted, convertedMatch)
	}

	return converted
}
