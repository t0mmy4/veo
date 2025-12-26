package redirect

import "testing"

type fakeFetcherFull struct {
	responses map[string]struct {
		body       string
		statusCode int
		headers    map[string][]string
	}
}

func (f *fakeFetcherFull) MakeRequestFull(rawURL string) (string, int, map[string][]string, error) {
	if r, ok := f.responses[rawURL]; ok {
		return r.body, r.statusCode, r.headers, nil
	}
	return "", 404, map[string][]string{"Content-Type": {"text/plain"}}, nil
}

func TestDetectClientRedirectURL_MetaRefresh(t *testing.T) {
	body := `<html><head><meta http-equiv="refresh" content="0;url=/next"></head></html>`
	got := DetectClientRedirectURL(body)
	if got != "/next" {
		t.Fatalf("expected /next, got %q", got)
	}
}

func TestDetectClientRedirectURL_JSLocation(t *testing.T) {
	body := `<html><script>window.location.href = '/login';</script></html>`
	got := DetectClientRedirectURL(body)
	if got != "/login" {
		t.Fatalf("expected /login, got %q", got)
	}
}

func TestDetectClientRedirectURL_LocationHrefNoPrefix(t *testing.T) {
	body := `<html><script>location.href = "/next";</script></html>`
	got := DetectClientRedirectURL(body)
	if got != "/next" {
		t.Fatalf("expected /next, got %q", got)
	}
}

func TestDetectClientRedirectURL_LocationReplaceNoPrefix(t *testing.T) {
	body := `<html><script>location.replace('/jump');</script></html>`
	got := DetectClientRedirectURL(body)
	if got != "/jump" {
		t.Fatalf("expected /jump, got %q", got)
	}
}

func TestDetectClientRedirectURL_NoScriptTagShouldNotMatchJS(t *testing.T) {
	body := `window.location.href = '/login'`
	got := DetectClientRedirectURL(body)
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestLooksLikeHTML_ByContentType(t *testing.T) {
	if !looksLikeHTML("text/html; charset=utf-8", "not html") {
		t.Fatalf("expected true")
	}
}

func TestLooksLikeHTML_ByBodyHeuristic(t *testing.T) {
	if !looksLikeHTML("", "<!DOCTYPE html><html><head></head><body></body></html>") {
		t.Fatalf("expected true")
	}
	if looksLikeHTML("application/json", `{"k":"v"}`) {
		t.Fatalf("expected false")
	}
}

func TestNormalizeRedirectLink(t *testing.T) {
	if normalizeRedirectLink("#section") != "" {
		t.Fatalf("expected empty for anchor-only link")
	}
	if normalizeRedirectLink("javascript:alert(1)") != "" {
		t.Fatalf("expected empty for javascript: link")
	}
	if normalizeRedirectLink("data:text/plain,hi") != "" {
		t.Fatalf("expected empty for data: link")
	}
	if normalizeRedirectLink("/ok") != "/ok" {
		t.Fatalf("expected /ok")
	}
}

func TestExecute_CycleRedirectStopsEarly(t *testing.T) {
	fetcher := &fakeFetcherFull{responses: map[string]struct {
		body       string
		statusCode int
		headers    map[string][]string
	}{
		"http://example.com/a": {
			body:       `<html><meta http-equiv="refresh" content="0;url=/b"></html>`,
			statusCode: 200,
			headers:    map[string][]string{"Content-Type": {"text/html"}},
		},
		"http://example.com/b": {
			body:       `<html><meta http-equiv="refresh" content="0;url=/a"></html>`,
			statusCode: 200,
			headers:    map[string][]string{"Content-Type": {"text/html"}},
		},
	}}

	resp, err := Execute("http://example.com/a", fetcher, &Config{MaxRedirects: 5, FollowRedirect: true, SameHostOnly: true})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.URL != "http://example.com/b" {
		t.Fatalf("expected stop on /b due to cycle detection, got %q", resp.URL)
	}
}

func TestExecute_OriginRedirectStopsEarly(t *testing.T) {
	fetcher := &fakeFetcherFull{responses: map[string]struct {
		body       string
		statusCode int
		headers    map[string][]string
	}{
		"http://example.com/login?origin=abc": {
			body:       `<html><meta http-equiv="refresh" content="0;url=/login?origin=def"></html>`,
			statusCode: 200,
			headers:    map[string][]string{"Content-Type": {"text/html"}},
		},
		"http://example.com/login?origin=def": {
			body:       `<html><meta http-equiv="refresh" content="0;url=/login?origin=ghi"></html>`,
			statusCode: 200,
			headers:    map[string][]string{"Content-Type": {"text/html"}},
		},
	}}

	resp, err := Execute("http://example.com/login?origin=abc", fetcher, &Config{MaxRedirects: 3, FollowRedirect: true, SameHostOnly: true})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.URL != "http://example.com/login?origin=abc" {
		t.Fatalf("expected stop on first origin redirect, got %q", resp.URL)
	}
}
