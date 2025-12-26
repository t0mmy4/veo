//go:build passive

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/network"
)

type Options struct {
	Addr              string
	StreamLargeBodies int64 // 当请求或响应体大于此字节时，转为 stream 模式
	SslInsecure       bool
	Upstream          string
}

type Proxy struct {
	Opts   *Options
	Addons []Addon

	entry    *entry
	attacker *attacker
}

// proxy.server req context key
var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:   opts,
		Addons: make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			logger.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyUrl(req)
	}
}

func (proxy *Proxy) getUpstreamProxyUrl(req *http.Request) (*url.URL, error) {
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyUrl, err := proxy.getUpstreamProxyUrl(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := network.CanonicalAddr(req.URL)
	if proxyUrl != nil {
		conn, err = network.GetProxyConn(ctx, proxyUrl, address, proxy.Opts.SslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}
