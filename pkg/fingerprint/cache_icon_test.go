package fingerprint

import (
	"crypto/md5"
	"fmt"
	"testing"
)

type mockClient struct {
	body       string
	statusCode int
	err        error
}

func (m *mockClient) MakeRequest(rawURL string) (string, int, error) {
	return m.body, m.statusCode, m.err
}

func TestIconCache(t *testing.T) {
	c := NewIconCache()
	client := &mockClient{body: "test_icon_data", statusCode: 200}
	expectedHash := fmt.Sprintf("%x", md5.Sum([]byte("test_icon_data")))

	// Test 1: GetHash (Cache Miss)
	hash, err := c.GetHash("http://example.com/icon.ico", client)
	if err != nil {
		t.Errorf("GetHash failed: %v", err)
	}
	if hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, hash)
	}

	// Test 2: GetHash (Cache Hit)
	client.body = "changed_data" // Client data changes, but cache should return old hash
	hash2, err := c.GetHash("http://example.com/icon.ico", client)
	if err != nil {
		t.Errorf("GetHash failed: %v", err)
	}
	if hash2 != expectedHash {
		t.Errorf("Cache miss? Expected %s, got %s", expectedHash, hash2)
	}

	// Test 3: Match Cache
	if _, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash); exists {
		t.Error("Match cache should be empty")
	}
	
	c.SetMatchResult("http://example.com/icon.ico", expectedHash, true)
	
	matched, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash)
	if !exists || !matched {
		t.Error("Match cache failed")
	}

	// Test 4: Clear
	c.Clear()
	if _, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash); exists {
		t.Error("Clear failed")
	}
}
