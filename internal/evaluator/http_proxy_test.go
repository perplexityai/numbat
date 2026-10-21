package evaluator

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
)

func TestProxyURLValidation(t *testing.T) {
	for _, raw := range []string{
		"", "http://proxy.example", "https://proxy.example/",
		"http://127.0.0.1:8080", "https://[::1]:65535", "http://[::1]",
	} {
		p := invocation(t).Profile
		p.ProxyURL = raw
		if err := p.Validate(); err != nil {
			t.Fatalf("valid proxy rejected: %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"proxy.example", "socks5://proxy.example", "http://", "https:///path",
		"http://:8080", "http://proxy.example:", "http://proxy.example:0",
		"http://proxy.example:65536", "http://proxy.example:-1", "http://proxy.example:bad",
		"http://[proxy.example]", "http://::1", "http://2001:db8::1:8080",
		"http://secret@proxy.example", "http://user:secret@proxy.example",
		"http://proxy.example?secret", "http://proxy.example?", "http://proxy.example#",
		"http://proxy.example#secret", "http://proxy.example/path", "http://proxy.example/%2f",
		" http://proxy.example", "http://proxy.example\n", "http://proxy.example/%",
		"http://" + strings.Repeat("x", 2048),
	} {
		p := invocation(t).Profile
		p.ProxyURL = raw
		err := p.Validate()
		if err == nil || strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("missing or unsafe validation for %q: %v", raw, err)
		}
		if h, err := NewHTTP(p, "synthetic-token"); err == nil || h != nil {
			t.Fatalf("invalid proxy accepted by constructor: %q", raw)
		}
	}
}

func TestProxyConfigurationIdentity(t *testing.T) {
	var c Config
	if err := decision.DecodeYAML([]byte("provider:\n  proxy_url: https://proxy.example:8443\n"), &c); err != nil {
		t.Fatal(err)
	}
	p := invocation(t).Profile
	direct := p.Digest()
	p.ProxyURL = c.Provider.ProxyURL
	if p.ProxyURL != "https://proxy.example:8443" || p.Digest() == direct {
		t.Fatal("proxy configuration was ignored or omitted from provider identity")
	}
	proxied := p.Digest()
	p.ProxyURL = "https://another-proxy.example:8443"
	if p.Digest() == proxied {
		t.Fatal("changing the proxy did not change provider identity")
	}
}

func TestExplicitProxyTransport(t *testing.T) {
	for _, mode := range []string{"http", "https", "direct", "disabled", "failed"} {
		t.Run(mode, func(t *testing.T) {
			var providerCalls, ambientCalls, proxyCalls atomic.Int32
			ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ambientCalls.Add(1)
				w.WriteHeader(http.StatusBadGateway)
			}))
			defer ambient.Close()
			for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				t.Setenv(key, ambient.URL)
			}
			for _, key := range []string{"NO_PROXY", "no_proxy"} {
				value := "*"
				if mode == "direct" {
					value = ""
				}
				t.Setenv(key, value)
			}
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" ||
					r.Header.Get("Authorization") != "Bearer synthetic-token" ||
					r.Header.Get("X-Fixture") != "provider-only" || r.TLS == nil {
					t.Error("provider request lost TLS, credentials or metadata")
				}
				var body struct {
					Model string `json:"model"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != "fixture-model" {
					t.Errorf("invalid provider request: %v", err)
				}
				_, _ = io.WriteString(w, `{"model":"fixture-model","answers":{"policy":{"type":"choice","choice":"violation","probabilities":{"violation":0.995,"permitted":0.003,"unknown":0.002}}}}`)
			}))
			defer provider.Close()
			target := strings.TrimPrefix(provider.URL, "https://")
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyCalls.Add(1)
				if r.Method != http.MethodConnect || r.Host != target ||
					r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" ||
					r.Header.Get("X-Fixture") != "" {
					t.Error("CONNECT leaked provider headers or used an unexpected destination")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if mode == "failed" {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer upstream.Close()
				client, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer client.Close()
				if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				if err := upstream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					t.Error(err)
					return
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					_, _ = io.Copy(upstream, buffered)
				}()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-done
			})
			proxy := httptest.NewUnstartedServer(handler)
			if mode == "https" {
				proxy.StartTLS()
			} else {
				proxy.Start()
			}
			defer proxy.Close()
			roots := x509.NewCertPool()
			roots.AddCert(provider.Certificate())
			if mode == "https" {
				roots.AddCert(proxy.Certificate())
			}
			in := invocation(t)
			in.Profile.Endpoint = provider.URL + "/v1/decisions"
			in.Profile.Headers = map[string]string{"X-Fixture": "provider-only"}
			if mode != "direct" {
				in.Profile.ProxyURL = proxy.URL
			}
			in.Binding.Enabled = mode != "disabled"
			got := Run(context.Background(), in, func(p Profile) (Provider, error) {
				h, err := NewHTTP(p, "synthetic-token")
				if err != nil {
					return nil, err
				}
				transport := h.client.Transport.(*http.Transport)
				if mode == "direct" && transport.Proxy != nil {
					t.Error("direct transport must not consult ambient proxy settings")
				}
				transport.TLSClientConfig.RootCAs = roots
				return h, nil
			})
			switch mode {
			case "disabled":
				if got.Status != "skipped" || got.DenyCandidate || providerCalls.Load() != 0 || proxyCalls.Load() != 0 {
					t.Fatalf("disabled evaluation used proxy or provider: %+v", got)
				}
			case "failed":
				if got.Status != "unavailable" || got.DenyCandidate || providerCalls.Load() != 0 || proxyCalls.Load() != 1 {
					t.Fatalf("proxy failure did not fail open without fallback: %+v", got)
				}
			default:
				if !got.Matched || !got.DenyCandidate || providerCalls.Load() != 1 {
					t.Fatalf("selected HTTPS request failed: %+v", got)
				}
				wantProxyCalls := int32(1)
				if mode == "direct" {
					wantProxyCalls = 0
				}
				if proxyCalls.Load() != wantProxyCalls {
					t.Fatalf("proxy calls=%d, want %d", proxyCalls.Load(), wantProxyCalls)
				}
			}
			if ambientCalls.Load() != 0 {
				t.Fatal("ambient proxy was used")
			}
		})
	}
}
