package report

import (
	"encoding/json"
	"fmt"

	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
)

// CombinedAPIResponse 统一的API/CLI JSON响应结构
type CombinedAPIResponse struct {
	Fingerprint []FingerprintAPIPage `json:"fingerprint,omitempty"`
	Dirscan     []DirscanAPIPage     `json:"dirscan,omitempty"`
}

type FingerprintAPIPage struct {
	URL         string                      `json:"url"`
	StatusCode  int                         `json:"status_code"`
	Title       string                      `json:"title,omitempty"`
	ContentType string                      `json:"content_type,omitempty"`
	DurationMs  int64                       `json:"duration_ms"`
	Matches     []SDKFingerprintMatchOutput `json:"matches,omitempty"`
}

type DirscanAPIPage struct {
	URL           string                      `json:"url"`
	StatusCode    int                         `json:"status_code"`
	Title         string                      `json:"title,omitempty"`
	ContentLength int64                       `json:"content_length"`
	ContentType   string                      `json:"content_type,omitempty"`
	DurationMs    int64                       `json:"duration_ms"`
	Fingerprints  []SDKFingerprintMatchOutput `json:"fingerprints,omitempty"`
}

type SDKFingerprintMatchOutput struct {
	RuleName    string `json:"rule_name"`
	RuleContent string `json:"rule_content,omitempty"`
}

func buildCombinedAPIResponse(dirPages []interfaces.HTTPResponse, fpPages []interfaces.HTTPResponse, matches []types.FingerprintMatch) CombinedAPIResponse {
	return CombinedAPIResponse{
		Fingerprint: makeFingerprintPageResults(fpPages, matches),
		Dirscan:     makeDirscanPageResults(dirPages),
	}
}

// GenerateCombinedJSON 生成合并 JSON（仅负责序列化，不做文件 IO）
func GenerateCombinedJSON(dirPages []interfaces.HTTPResponse, fingerprintPages []interfaces.HTTPResponse, matches []types.FingerprintMatch) (string, error) {
	result := buildCombinedAPIResponse(dirPages, fingerprintPages, matches)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}
	return string(data), nil
}

// makeDirscanPageResults 构造目录扫描结果列表
func makeDirscanPageResults(pages []interfaces.HTTPResponse) []DirscanAPIPage {
	if len(pages) == 0 {
		return nil
	}

	results := make([]DirscanAPIPage, 0, len(pages))
	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		results = append(results, DirscanAPIPage{
			URL:           page.URL,
			StatusCode:    page.StatusCode,
			Title:         page.Title,
			ContentLength: length,
			DurationMs:    page.Duration,
			ContentType:   page.ContentType,
			Fingerprints:  toSDKMatchesFromInterfaces(page.Fingerprints),
		})
	}

	return results
}

// makeFingerprintPageResults 构造指纹识别结果列表
func makeFingerprintPageResults(pages []interfaces.HTTPResponse, matches []types.FingerprintMatch) []FingerprintAPIPage {
	if len(pages) == 0 && len(matches) == 0 {
		return nil
	}

	matchMap := groupMatchesByURL(matches)
	results := make([]FingerprintAPIPage, 0, len(pages)+len(matchMap))
	seen := make(map[string]bool, len(pages))

	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		existing := toSDKMatchesFromInterfaces(page.Fingerprints)
		fps := matchMap[page.URL]
		if len(fps) > 0 {
			existing = mergeFingerprintOutputs(existing, fps)
		}
		results = append(results, FingerprintAPIPage{
			URL:         page.URL,
			StatusCode:  page.StatusCode,
			Title:       page.Title,
			ContentType: page.ContentType,
			DurationMs:  page.Duration,
			Matches:     existing,
		})
		seen[page.URL] = true
	}

	// 对于仅有指纹匹配记录但没有响应的URL，也进行输出
	for url, fps := range matchMap {
		if seen[url] {
			continue
		}
		if len(fps) == 0 {
			continue
		}
		results = append(results, FingerprintAPIPage{
			URL:     url,
			Matches: fps,
		})
	}

	return results
}

// groupMatchesByURL 将指纹匹配结果按URL分组
func groupMatchesByURL(matches []types.FingerprintMatch) map[string][]SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	grouped := make(map[string][]SDKFingerprintMatchOutput)
	for _, match := range matches {
		url := match.URL
		grouped[url] = append(grouped[url], SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.DSLMatched,
		})
	}
	return grouped
}

func toSDKMatchesFromInterfaces(matches []interfaces.FingerprintMatch) []SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	outputs := make([]SDKFingerprintMatchOutput, 0, len(matches))
	for _, match := range matches {
		outputs = append(outputs, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.Matcher,
		})
	}

	return outputs
}

func mergeFingerprintOutputs(base []SDKFingerprintMatchOutput, extra []SDKFingerprintMatchOutput) []SDKFingerprintMatchOutput {
	if len(extra) == 0 {
		return base
	}

	if len(base) == 0 {
		merged := make([]SDKFingerprintMatchOutput, len(extra))
		copy(merged, extra)
		return merged
	}

	keyIndex := make(map[string]int, len(base))
	for idx, item := range base {
		key := item.RuleName + "|" + item.RuleContent
		keyIndex[key] = idx
	}

	for _, item := range extra {
		key := item.RuleName + "|" + item.RuleContent
		if _, ok := keyIndex[key]; ok {
			continue
		}
		keyIndex[key] = len(base)
		base = append(base, item)
	}

	return base
}
