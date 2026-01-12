package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/processor"
)

type similarProbe struct {
	idx       int
	target    string
	remoteIP  string
	signature string
	status    int
	isHTTPS   bool
	timeout   bool
	ok        bool
}

type similarStats struct {
	Total    int
	Deduped  int
	Timeouts int
	Failed   int
	Kept     int
}

type similarPair struct {
	Target    string
	SimilarTo string
}

type similarReport struct {
	Stats          similarStats
	SimilarPairs   []similarPair
	TimeoutTargets []string
}

func (sc *ScanController) checkSimilarTargetsWithReport(ctx context.Context, targets []string) ([]string, similarReport) {
	report := similarReport{Stats: similarStats{Total: len(targets)}}
	if len(targets) <= 1 || sc.requestProcessor == nil {
		report.Stats.Kept = len(targets)
		return targets, report
	}

	logSimilarInfo(sc, "开始相似目标检查: %d", len(targets))

	reqProcessor := sc.requestProcessor.CloneWithContext("check-similar", 0)
	reqProcessor.SetStatsUpdater(nil)
	reqProcessor.SetBatchMode(true)

	iconCache := fingerprint.NewIconCache()

	maxConcurrent := reqProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	if maxConcurrent > len(targets) {
		maxConcurrent = len(targets)
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	jobs := make(chan int)
	results := make(chan similarProbe, len(targets))

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			res := similarProbe{idx: idx, target: targets[idx]}
			if ctx != nil {
				select {
				case <-ctx.Done():
					results <- res
					continue
				default:
				}
			}

			resp, err := reqProcessor.RequestOnceWithHeaders(ctx, targets[idx], nil)
			if err != nil || resp == nil {
				res.timeout = processor.IsTimeoutOrCanceledError(err)
				results <- res
				continue
			}

			iconHash := fetchIconHash(resp.URL, iconCache, reqProcessor)
			signature, signatureInfo := buildSignatureInfo(resp, iconHash)
			res.signature = signature
			if res.signature == "" {
				results <- res
				continue
			}

			res.ok = true
			res.remoteIP = strings.TrimSpace(resp.RemoteIP)
			res.status = resp.StatusCode
			res.isHTTPS = isHTTPSURL(targets[idx])
			logSimilarSignatureDebug(res.target, res.remoteIP, res.signature, signatureInfo)
			results <- res
		}
	}

	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go worker()
	}

	for idx := range targets {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(results)

	ipGroups := make(map[string]map[string][]similarProbe)
	failed := make([]int, 0)
	timeouts := 0
	timeoutTargets := make([]string, 0)
	for res := range results {
		if res.ok {
			ipKey := res.remoteIP
			if ipKey == "" {
				ipKey = fmt.Sprintf("unknown-%d", res.idx)
			}
			if ipGroups[ipKey] == nil {
				ipGroups[ipKey] = make(map[string][]similarProbe)
			}
			ipGroups[ipKey][res.signature] = append(ipGroups[ipKey][res.signature], res)
			continue
		}
		failed = append(failed, res.idx)
		if res.timeout {
			timeouts++
			timeoutTargets = append(timeoutTargets, res.target)
		}
	}

	keep := make([]bool, len(targets))
	if !shouldDropFailedSimilar(sc) {
		for _, idx := range failed {
			if idx >= 0 && idx < len(keep) {
				keep[idx] = true
			}
		}
	}

	deduped := 0
	similarPairs := make([]similarPair, 0)
	for _, groups := range ipGroups {
		for _, group := range groups {
			if len(group) == 0 {
				continue
			}
			best := group[0]
			for i := 1; i < len(group); i++ {
				if preferSimilarCandidate(group[i], best) {
					best = group[i]
				}
			}
			keep[best.idx] = true
			if len(group) > 1 {
				deduped += len(group) - 1
				for _, item := range group {
					if item.idx == best.idx {
						continue
					}
					similarPairs = append(similarPairs, similarPair{
						Target:    item.target,
						SimilarTo: best.target,
					})
				}
			}
		}
	}

	kept := make([]string, 0, len(targets)-deduped)
	for i, target := range targets {
		if keep[i] {
			kept = append(kept, target)
		}
	}

	report.Stats.Deduped = deduped
	report.Stats.Timeouts = timeouts
	report.Stats.Failed = len(failed)
	report.Stats.Kept = len(kept)
	report.SimilarPairs = similarPairs
	report.TimeoutTargets = timeoutTargets

	logSimilarInfo(sc, "相似目标检查完成: 输入 %d, 保留 %d, 去重 %d, 失败 %d", len(targets), len(kept), deduped, len(failed))
	return kept, report
}

func preferSimilarCandidate(a, b similarProbe) bool {
	if a.status == 200 && b.status != 200 {
		return true
	}
	if a.status != 200 && b.status == 200 {
		return false
	}
	if a.isHTTPS && !b.isHTTPS {
		return true
	}
	if !a.isHTTPS && b.isHTTPS {
		return false
	}
	return a.idx < b.idx
}

type signatureInfo struct {
	StatusLine  string
	Server      string
	Title       string
	ContentType string
	IconHash    string
}

func buildSignatureInfo(resp *interfaces.HTTPResponse, iconHash string) (string, signatureInfo) {
	if resp == nil {
		return "", signatureInfo{}
	}

	info := signatureInfo{
		StatusLine:  normalizeStatusLine(resp.StatusCode),
		Server:      normalizeServer(resp.Server),
		Title:       normalizeTitle(resp.Title),
		ContentType: normalizeContentType(resp.ContentType),
		IconHash:    normalizeIconHash(iconHash),
	}

	signature := fmt.Sprintf("%s|%s|%s|%s|%s", info.StatusLine, info.Server, info.Title, info.ContentType, info.IconHash)
	return signature, info
}

func normalizeTitle(title string) string {
	title = strings.TrimSpace(strings.ToLower(title))
	if title == "" {
		return "empty"
	}
	return title
}

func normalizeServer(server string) string {
	server = strings.TrimSpace(strings.ToLower(server))
	if server == "" {
		return "unknown"
	}
	return server
}

func normalizeStatusLine(statusCode int) string {
	if statusCode <= 0 {
		return "unknown"
	}
	text := http.StatusText(statusCode)
	if text == "" {
		return fmt.Sprintf("%d", statusCode)
	}
	return fmt.Sprintf("%d %s", statusCode, text)
}

func normalizeContentType(contentType string) string {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	if contentType == "" {
		return "unknown"
	}
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	return contentType
}

func normalizeIconHash(hash string) string {
	hash = strings.TrimSpace(strings.ToLower(hash))
	if hash == "" {
		return "none"
	}
	return hash
}

func logSimilarSignatureDebug(target, remoteIP, signature string, info signatureInfo) {
	ip := strings.TrimSpace(remoteIP)
	if ip == "" {
		ip = "unknown"
	}
	logger.Debugf("相似度要素: %s | IP=%s | 状态=%s | Server=%s | Title=%s | Content-Type=%s | IconMD5=%s | 签名=%s",
		target,
		ip,
		info.StatusLine,
		info.Server,
		info.Title,
		info.ContentType,
		info.IconHash,
		signature,
	)
}

func fetchIconHash(rawURL string, cache *fingerprint.IconCache, client httpclient.HTTPClientInterface) string {
	if cache == nil || client == nil {
		return ""
	}
	iconURL := buildIconURL(rawURL)
	if iconURL == "" {
		return ""
	}
	hash, err := cache.GetHash(iconURL, client)
	if err != nil {
		return ""
	}
	return hash
}

func buildIconURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path = "/favicon.ico"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func shouldDropFailedSimilar(sc *ScanController) bool {
	if sc == nil || sc.args == nil {
		return false
	}
	return sc.args.CheckSimilarOnly
}

func logSimilarInfo(sc *ScanController, format string, args ...interface{}) {
	if sc == nil || sc.args == nil || sc.args.CheckSimilarOnly {
		return
	}
	logger.Infof(format, args...)
}

func isHTTPSURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(raw), "https://")
}
