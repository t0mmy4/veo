package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
)

// CombinedAPIResponse 统一的API/CLI JSON响应结构
type CombinedAPIResponse struct {
	Fingerprint []FingerprintAPIPage `json:"fingerprint,omitempty"`
	Dirscan     []DirscanAPIPage     `json:"dirscan,omitempty"`
}

type FingerprintAPIPage struct {
	URL           string                      `json:"url"`
	StatusCode    int                         `json:"status_code"`
	Title         string                      `json:"title,omitempty"`
	ContentLength int64                       `json:"content_length"`
	ContentType   string                      `json:"content_type,omitempty"`
	DurationMs    int64                       `json:"duration_ms"`
	Matches       []SDKFingerprintMatchOutput `json:"matches,omitempty"`
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
	Snippet     string `json:"snippet,omitempty"`
}

type fingerprintMatchGroup struct {
	URL     string
	Matches []SDKFingerprintMatchOutput
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
	data, err := json.Marshal(result)
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
	index := make(map[string]int, len(pages))

	for _, page := range pages {
		key := NormalizeFingerprintURLKey(page.URL)
		group := matchMap[key]
		var fps []SDKFingerprintMatchOutput
		if group != nil {
			fps = group.Matches
		}
		if existingIdx, ok := index[key]; ok {
			existing := results[existingIdx]
			existing.Matches = mergeFingerprintOutputs(existing.Matches, toSDKMatchesFromInterfaces(page.Fingerprints))
			if len(fps) > 0 {
				existing.Matches = mergeFingerprintOutputs(existing.Matches, fps)
			}
			if existing.ContentLength == 0 {
				if page.ContentLength > 0 {
					existing.ContentLength = page.ContentLength
				} else if page.Length > 0 {
					existing.ContentLength = page.Length
				}
			}
			if existing.StatusCode == 0 {
				existing.StatusCode = page.StatusCode
			}
			if existing.Title == "" {
				existing.Title = page.Title
			}
			if existing.ContentType == "" {
				existing.ContentType = page.ContentType
			}
			if existing.DurationMs == 0 {
				existing.DurationMs = page.Duration
			}
			results[existingIdx] = existing
		} else {
			contentLength := page.ContentLength
			if contentLength == 0 {
				contentLength = page.Length
			}
			existing := toSDKMatchesFromInterfaces(page.Fingerprints)
			if len(fps) > 0 {
				existing = mergeFingerprintOutputs(existing, fps)
			}
			results = append(results, FingerprintAPIPage{
				URL:           page.URL,
				StatusCode:    page.StatusCode,
				Title:         page.Title,
				ContentLength: contentLength,
				ContentType:   page.ContentType,
				DurationMs:    page.Duration,
				Matches:       existing,
			})
			index[key] = len(results) - 1
		}
		delete(matchMap, key)
	}

	// 对于仅有指纹匹配记录但没有响应的URL，也进行输出
	for _, group := range matchMap {
		if group == nil || len(group.Matches) == 0 {
			continue
		}
		results = append(results, FingerprintAPIPage{
			URL:     group.URL,
			Matches: group.Matches,
		})
	}

	return results
}

// groupMatchesByURL 将指纹匹配结果按URL分组
func groupMatchesByURL(matches []types.FingerprintMatch) map[string]*fingerprintMatchGroup {
	if len(matches) == 0 {
		return nil
	}

	grouped := make(map[string]*fingerprintMatchGroup)
	for _, match := range matches {
		key := NormalizeFingerprintURLKey(match.URL)
		ruleContent := match.Matcher
		if ruleContent == "" {
			ruleContent = match.DSLMatched
		}
		group := grouped[key]
		if group == nil {
			group = &fingerprintMatchGroup{
				URL: match.URL,
			}
			grouped[key] = group
		}
		group.Matches = append(group.Matches, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: ruleContent,
			Snippet:     match.Snippet,
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
		ruleContent := match.Matcher
		if ruleContent == "" {
			ruleContent = match.DSLMatched
		}
		outputs = append(outputs, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: ruleContent,
			Snippet:     match.Snippet,
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
		if baseIdx, ok := keyIndex[key]; ok {
			if base[baseIdx].Snippet == "" && item.Snippet != "" {
				base[baseIdx].Snippet = item.Snippet
			}
			continue
		}
		keyIndex[key] = len(base)
		base = append(base, item)
	}

	return base
}

// NormalizeFingerprintURLKey 统一指纹结果的URL归一化键
func NormalizeFingerprintURLKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return trimmed
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)

	host := strings.ToLower(parsed.Host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (parsed.Scheme == "http" && p == "80") || (parsed.Scheme == "https" && p == "443") {
			host = h
		}
	}
	parsed.Host = host

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed.String()
}
