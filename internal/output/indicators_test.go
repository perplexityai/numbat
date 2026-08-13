package output

import (
	"fmt"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// findInd returns the indicator with the given type and value, or nil.
func findInd(inds []Indicator, typ, val string) *Indicator {
	for i := range inds {
		if inds[i].Type == typ && inds[i].Value == val {
			return &inds[i]
		}
	}
	return nil
}

// A network.indicator URL contributes both a canonical url indicator and its
// host as a domain indicator; the same external host seen across events dedupes
// to one domain with a count, bounded by first/last seen.
func TestIndicatorsURLYieldsURLAndDomain(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://Evil.Example.COM/path#frag", SourceAgent: model.AgentClaudeCode, EventID: "e1", SessionID: "s1", ProjectPath: "/home/dev/proj", Timestamp: "2026-06-02T10:00:00Z"},
		{EventType: model.EventCommandExec, Command: "curl https://evil.example.com/other 2>/dev/null", SourceAgent: model.AgentCodex, EventID: "e2", Timestamp: "2026-06-02T10:00:05Z"},
	}
	inds := Indicators(events)

	// Host is lowercased and the fragment stripped from the canonical URL.
	if u := findInd(inds, IndicatorURL, "https://evil.example.com/path"); u == nil {
		t.Errorf("canonical url indicator missing; got %+v", inds)
	}
	dom := findInd(inds, IndicatorDomain, "evil.example.com")
	if dom == nil || dom.Count != 2 {
		t.Fatalf("domain indicator = %+v, want count 2 (deduped across two events)", dom)
	}
	if dom.FirstSeen != "2026-06-02T10:00:00Z" || dom.LastSeen != "2026-06-02T10:00:05Z" {
		t.Errorf("domain first/last = %q/%q, want 10:00:00/10:00:05", dom.FirstSeen, dom.LastSeen)
	}
	if dom.SampleSourceAgent != model.AgentClaudeCode || dom.SampleEventID != "e1" {
		t.Errorf("domain sample = %q/%q, want claude-code/e1", dom.SampleSourceAgent, dom.SampleEventID)
	}
	if dom.SampleSessionID != "s1" || dom.SampleProjectPathHash != model.HashPath("/home/dev/proj") {
		t.Errorf("domain sample context = %q/%q, want session/project hash", dom.SampleSessionID, dom.SampleProjectPathHash)
	}
}

func TestIndicatorsTrimMarkdownBoldFromURL(t *testing.T) {
	inds := Indicators([]model.Event{
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "Done: **review https://example.com/pull/290**",
			EventID:        "e1",
		},
		{
			EventType: model.EventNetworkIndicator,
			URL:       "https://example.com/search/*",
			EventID:   "e2",
		},
		{
			EventType: model.EventNetworkIndicator,
			URL:       "https://example.com/search/**",
			EventID:   "e3",
		},
		{
			EventType: model.EventCommandExec,
			Command:   "printf '%s' '**' && curl 'https://example.com/command/**'",
			EventID:   "e4",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "The glob ** matches recursively; see https://example.com/prose/**",
			EventID:        "e5",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: `Escaped \**review and https://example.com/escaped/**`,
			EventID:        "e6",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "Code: `**review` https://example.com/code/**",
			EventID:        "e7",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "***review https://example.com/triple/***",
			EventID:        "e8",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "Code: ``**review https://example.com/double-code/**``",
			EventID:        "e9",
		},
		{
			EventType:      model.EventMessageAssistant,
			ContentPreview: "```\n**review https://example.com/fenced/**\n```",
			EventID:        "e10",
		},
	})
	if findInd(inds, IndicatorURL, "https://example.com/pull/290") == nil {
		t.Errorf("Markdown-delimited URL missing; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://example.com/pull/290**") != nil {
		t.Errorf("Markdown closing marker retained; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://example.com/search/*") == nil {
		t.Errorf("single literal trailing asterisk should be preserved; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://example.com/search/**") == nil {
		t.Errorf("literal trailing asterisks should be preserved; got %+v", inds)
	}
	for _, value := range []string{
		"https://example.com/command/**",
		"https://example.com/prose/**",
		"https://example.com/escaped/**",
		"https://example.com/code/**",
		"https://example.com/triple/***",
		"https://example.com/double-code/**",
		"https://example.com/fenced/**",
	} {
		if findInd(inds, IndicatorURL, value) == nil {
			t.Errorf("literal URL %q should be preserved; got %+v", value, inds)
		}
	}
}

func TestIndicatorsUseContentBeyondPreview(t *testing.T) {
	var ev model.Event
	ev.EventID = "deep-content"
	ev.EventType = model.EventPromptUser
	ev.SetContent(strings.Repeat("padding ", 40)+"https://deep.example/path", true)
	if strings.Contains(ev.ContentPreview, "deep.example") {
		t.Fatal("test indicator unexpectedly fits in preview")
	}
	inds := Indicators([]model.Event{ev})
	if findInd(inds, IndicatorURL, "https://deep.example/path") == nil {
		t.Fatalf("deep content indicator missing: %+v", inds)
	}
}

func TestIndicatorsFirstLastSeenUsesTimeOrdering(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "curl https://evil.example/later", EventID: "e1", Timestamp: "2026-06-02T10:00:00-05:00"},
		{EventType: model.EventCommandExec, Command: "curl https://evil.example/earlier", EventID: "e2", Timestamp: "2026-06-02T14:00:00Z"},
	}
	inds := Indicators(events)
	dom := findInd(inds, IndicatorDomain, "evil.example")
	if dom == nil {
		t.Fatalf("domain indicator missing; got %+v", inds)
	}
	if dom.FirstSeen != "2026-06-02T14:00:00Z" || dom.LastSeen != "2026-06-02T10:00:00-05:00" {
		t.Fatalf("first/last = %q/%q, want absolute-time ordering across offsets", dom.FirstSeen, dom.LastSeen)
	}
}

func TestIndicatorsOmitEmptyProjectHash(t *testing.T) {
	inds := Indicators([]model.Event{{
		EventType: model.EventNetworkIndicator,
		URL:       "https://evil.example/path",
		EventID:   "e1",
	}})
	dom := findInd(inds, IndicatorDomain, "evil.example")
	if dom == nil {
		t.Fatalf("domain indicator missing; got %+v", inds)
	}
	if dom.SampleProjectPathHash != "" {
		t.Fatalf("empty project path emitted hash %q", dom.SampleProjectPathHash)
	}
}

// Loopback, RFC1918/private, link-local IPs, and *.local names are dropped as
// non-actionable noise — including a URL whose host is one of them.
func TestIndicatorsFiltersNoise(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "curl http://127.0.0.1:8080/x", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "ssh 10.0.0.5 && ping 192.168.1.1", EventID: "e2"},
		{EventType: model.EventCommandExec, Command: "dig fileserver.local", EventID: "e3"},
	}
	inds := Indicators(events)
	if len(inds) != 0 {
		t.Errorf("expected all-noise input to yield 0 indicators, got %d: %+v", len(inds), inds)
	}
}

// Shared-hosting, raw-content, object-storage, and registry domains are emitted:
// they are enrichment input, and broad suffix filtering can hide attacker-owned
// paths or buckets.
func TestIndicatorsKeepsSharedHostingValues(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://raw.githubusercontent.com/attacker/payload/main/run.sh", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://storage.googleapis.com/evil-bucket/payload", EventID: "e2"},
	}
	inds := Indicators(events)
	if findInd(inds, IndicatorDomain, "raw.githubusercontent.com") == nil {
		t.Errorf("raw.githubusercontent.com must be emitted, not dropped; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://raw.githubusercontent.com/attacker/payload/main/run.sh") == nil {
		t.Errorf("attacker raw-content URL must be emitted; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "storage.googleapis.com") == nil {
		t.Errorf("storage.googleapis.com must be emitted, not dropped; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://storage.googleapis.com/evil-bucket/payload") == nil {
		t.Errorf("exfil-bucket URL must be emitted; got %+v", inds)
	}
}

func TestIndicatorsCanonicalizesRootDotAndPunycodeHost(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://Evil.Example.:443/path#frag", EventID: "e1"},
		{EventType: model.EventNetworkIndicator, URL: "https://xn--e1afmkfd.xn--p1ai/drop", EventID: "e2"},
		{EventType: model.EventNetworkIndicator, URL: "https://.invalid.example/drop", EventID: "e3"},
	}
	inds := Indicators(events)
	if findInd(inds, IndicatorURL, "https://evil.example/path") == nil {
		t.Errorf("root-dot/default-port URL should be canonicalized; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("root-dot host should be emitted without the dot; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "xn--e1afmkfd.xn--p1ai") == nil {
		t.Errorf("punycode IDN host should be accepted; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "invalid.example") != nil {
		t.Errorf("leading-dot host must not be repaired into a valid domain; got %+v", inds)
	}
}

// A real external IPv4, a URL host as a domain, an email, and md5/sha1/sha256
// hashes embedded in command output are each typed correctly. Hash case is
// normalized. Domains are sourced from URL hosts (high precision), not mined from
// bare free text — a bare token like "models.rs" must not be typed as a domain.
func TestIndicatorsTypesIPsHashesEmail(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "curl http://8.8.8.8/payload", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://malware.bad.example/drop", EventID: "e2"},
		{EventType: model.EventMessageAssistant, ContentPreview: "contact attacker@bad.example for the key", EventID: "e3"},
		{EventType: model.EventCommandExec, Command: "echo d41d8cd98f00b204e9800998ecf8427e", EventID: "e4"},
		{EventType: model.EventCommandExec, Command: "sha256sum: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", EventID: "e5"},
		{EventType: model.EventCommandExec, Command: "shasum da39a3ee5e6b4b0d3255bfef95601890afd80709 file", EventID: "e6"},
	}
	inds := Indicators(events)

	if findInd(inds, IndicatorIPv4, "8.8.8.8") == nil {
		t.Errorf("ipv4 8.8.8.8 missing; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "malware.bad.example") == nil {
		t.Errorf("domain malware.bad.example missing")
	}
	if findInd(inds, IndicatorEmail, "attacker@bad.example") == nil {
		t.Errorf("email indicator missing")
	}
	if findInd(inds, IndicatorMD5, "d41d8cd98f00b204e9800998ecf8427e") == nil {
		t.Errorf("md5 indicator missing")
	}
	// sha256 hash is lowercased on the way in.
	if findInd(inds, IndicatorSHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == nil {
		t.Errorf("sha256 indicator missing (or not lowercased)")
	}
	if findInd(inds, IndicatorSHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == nil {
		t.Errorf("sha1 indicator missing")
	}
}

// A credential embedded in a mined field is redacted BEFORE extraction, so the
// emitted URL never carries the signature value while the host is still typed.
func TestIndicatorsRedactsBeforeExtraction(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://exfil.example/upload?api_key=deadbeefcafe&id=1", EventID: "e1"},
	}
	inds := Indicators(events)
	for _, ind := range inds {
		if ind.Type == IndicatorURL && strings.Contains(ind.Value, "deadbeefcafe") {
			t.Errorf("emitted url leaked credential: %q", ind.Value)
		}
	}
	if findInd(inds, IndicatorDomain, "exfil.example") == nil {
		t.Errorf("host should still be typed after redaction; got %+v", inds)
	}
}

// Dotted tokens that are not domains (version strings, source filenames), bare
// hex that is part of a UUID, and a Go module pin that @ makes look like an email
// are NOT mistyped as indicators.
func TestIndicatorsRejectsNonIndicatorShapes(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "go 1.25.0 build models.rs version 2.0", EventID: "e1"},
		{EventType: model.EventMessageAssistant, ContentPreview: "session 550e8400-e29b-41d4-a716-446655440000 started", EventID: "e2"},
		// A Go toolchain module path: the '@' looks like an email but the domain
		// has bare-numeric labels, so it must not be typed as an email.
		{EventType: model.EventCommandExec, Command: "ls golang.org/toolchain@v0.0.1-go1.25.0.linux-amd64/bin/go", EventID: "e3"},
	}
	inds := Indicators(events)
	if len(inds) != 0 {
		t.Errorf("non-indicator shapes should yield 0 indicators, got %d: %+v", len(inds), inds)
	}
}

// Empty fields contribute nothing and the output is sorted by (type, value) for
// deterministic, byte-stable output.
func TestIndicatorsSkipsEmptyAndIsSorted(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://zeta.example https://alpha.example", EventID: "e2"},
	}
	inds := Indicators(events)
	for _, ind := range inds {
		if ind.Value == "" {
			t.Errorf("empty-valued indicator emitted: %+v", ind)
		}
	}
	var domains []string
	for _, ind := range inds {
		if ind.Type == IndicatorDomain {
			domains = append(domains, ind.Value)
		}
	}
	if len(domains) != 2 || domains[0] != "alpha.example" || domains[1] != "zeta.example" {
		t.Errorf("domain indicators = %v, want [alpha.example zeta.example] sorted", domains)
	}
}

// URL userinfo is stripped during canonicalization: the emitted url never
// carries the password, and the email miner must not republish the userinfo as a
// bogus email. The host is still typed as a domain.
func TestIndicatorsStripsURLUserinfo(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://user:secretpw123@evil.example/x", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://token@host.example/y", EventID: "e2"},
	}
	inds := Indicators(events)
	for _, ind := range inds {
		if strings.Contains(ind.Value, "secretpw123") || strings.Contains(ind.Value, "user:") {
			t.Errorf("indicator leaked userinfo: %+v", ind)
		}
		if ind.Type == IndicatorEmail {
			t.Errorf("URL userinfo must not be typed as email: %+v", ind)
		}
	}
	if findInd(inds, IndicatorURL, "https://evil.example/x") == nil {
		t.Errorf("canonical url should drop userinfo; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("host should still be typed after userinfo strip; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "host.example") == nil {
		t.Errorf("second host should be typed; got %+v", inds)
	}
}

// URL userinfo must not be reclassified by the standalone IPv4/hash miners. An IP
// or hash that appears only as a URL's user:pass credential is decided by URL
// canonicalization (and dropped); republishing it as a bare ipv4/md5 indicator
// would both mis-type and leak the credential. A genuine host outside the userinfo
// is still emitted.
func TestIndicatorsUserinfoNotMinedAsIPOrHash(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef" // 32 hex == md5 length
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "curl https://8.8.8.8@evil.example/x", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://" + hash + "@evil.example/y", EventID: "e2"},
	}
	inds := Indicators(events)
	if ind := findInd(inds, IndicatorIPv4, "8.8.8.8"); ind != nil {
		t.Errorf("URL userinfo must not be mined as ipv4: %+v", ind)
	}
	if ind := findInd(inds, IndicatorMD5, hash); ind != nil {
		t.Errorf("URL userinfo must not be mined as md5: %+v", ind)
	}
	for _, ind := range inds {
		if strings.Contains(ind.Value, hash) && ind.Type != IndicatorURL {
			// even the url indicator drops userinfo, so the hash must appear nowhere
			t.Errorf("userinfo hash leaked into indicator: %+v", ind)
		}
		if ind.Type == IndicatorURL && strings.Contains(ind.Value, hash) {
			t.Errorf("canonical url must drop userinfo hash: %+v", ind)
		}
	}
	// The real host is still typed (userinfo fencing must not blank the whole field).
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("host outside userinfo should still be typed; got %+v", inds)
	}
}

func TestIndicatorsDSNUserinfoNotMined(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef"
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "connect postgres://8.8.8.8:secret@db.example:5432/app", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "connect redis://" + hash + ":secret@cache.example:6379/0", EventID: "e2"},
		{EventType: model.EventCommandExec, Command: "connect postgres://user:secret@db.example/app then https://evil.example/x", EventID: "e3"},
		{EventType: model.EventCommandExec, Command: "connect postgres://user:p!$&'()*+,;=ss@9.9.9.9/db", EventID: "e4"},
		{EventType: model.EventCommandExec, Command: "connect redis://user:secret@[2001:4860:4860::8888]:6379/0", EventID: "e5"},
	}
	inds := Indicators(events)
	if ind := findInd(inds, IndicatorIPv4, "8.8.8.8"); ind != nil {
		t.Errorf("DSN username must not be mined as ipv4: %+v", ind)
	}
	if ind := findInd(inds, IndicatorMD5, hash); ind != nil {
		t.Errorf("DSN username must not be mined as md5: %+v", ind)
	}
	for _, ind := range inds {
		if ind.Type == IndicatorEmail {
			t.Errorf("redacted DSN userinfo must not become an email: %+v", ind)
		}
	}
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("indicator outside DSN was lost: %+v", inds)
	}
	for _, host := range []string{"db.example", "cache.example"} {
		if findInd(inds, IndicatorDomain, host) == nil {
			t.Errorf("DSN host %q was lost: %+v", host, inds)
		}
	}
	if findInd(inds, IndicatorIPv4, "9.9.9.9") == nil {
		t.Errorf("DSN IPv4 host was lost: %+v", inds)
	}
	if findInd(inds, IndicatorIPv6, "2001:4860:4860::8888") == nil {
		t.Errorf("DSN IPv6 host was lost: %+v", inds)
	}
}

func TestIndicatorsRetainDSNHostBeforeDelimitedProse(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "connect postgres://user:secret@db.example:5432;ops@example.com", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "connect redis://user:secret@cache.example:6379,admin@example.com", EventID: "e2"},
		{EventType: model.EventCommandExec, Command: "connect amqp://user:secret@broker.example:5672&owner@example.com", EventID: "e3"},
	}
	inds := Indicators(events)
	for _, host := range []string{"db.example", "cache.example", "broker.example"} {
		if findInd(inds, IndicatorDomain, host) == nil {
			t.Errorf("indicator %q was lost: %+v", host, inds)
		}
	}
	for _, email := range []string{"ops@example.com", "admin@example.com", "owner@example.com"} {
		if findInd(inds, IndicatorEmail, email) == nil {
			t.Errorf("indicator %q was lost: %+v", email, inds)
		}
	}
}

// An uppercase/mixed-case URL scheme must be recognized as a URL so its userinfo
// is fenced off the standalone miners exactly like a lowercase scheme. Without a
// case-insensitive scheme match, HTTPS://8.8.8.8@evil.example/x would skip both
// canonicalization and URL-blanking, letting the bare ipv4/hash/email miners
// re-leak the userinfo (ipv4=8.8.8.8, md5=<hex>, a bogus email) — while the real
// host evil.example must still be captured and the canonical url must carry a
// lowercased scheme.
func TestIndicatorsUppercaseSchemeUserinfoFenced(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef" // 32 hex == md5 length
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "curl HTTPS://8.8.8.8@evil.example/x", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl Https://" + hash + "@evil.example/y", EventID: "e2"},
		{EventType: model.EventNetworkIndicator, URL: "HTTP://admin@8.8.8.8@evil.example/z", EventID: "e3"},
	}
	inds := Indicators(events)
	if ind := findInd(inds, IndicatorIPv4, "8.8.8.8"); ind != nil {
		t.Errorf("uppercase-scheme URL userinfo must not be mined as ipv4: %+v", ind)
	}
	if ind := findInd(inds, IndicatorMD5, hash); ind != nil {
		t.Errorf("uppercase-scheme URL userinfo must not be mined as md5: %+v", ind)
	}
	for _, ind := range inds {
		if ind.Type == IndicatorEmail {
			t.Errorf("uppercase-scheme URL userinfo must not be mined as email: %+v", ind)
		}
		if strings.Contains(ind.Value, hash) && ind.Type != IndicatorURL {
			t.Errorf("userinfo hash leaked into indicator: %+v", ind)
		}
		if ind.Type == IndicatorURL && strings.Contains(ind.Value, hash) {
			t.Errorf("canonical url must drop userinfo hash: %+v", ind)
		}
	}
	// The real host outside the userinfo is still captured.
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("host outside uppercase-scheme userinfo should still be typed; got %+v", inds)
	}
	// The canonical url is emitted with a lowercased scheme.
	sawLowerScheme := false
	for _, ind := range inds {
		if ind.Type == IndicatorURL {
			if strings.HasPrefix(ind.Value, "https://") || strings.HasPrefix(ind.Value, "http://") {
				sawLowerScheme = true
			} else {
				t.Errorf("canonical url scheme must be lowercased; got %+v", ind)
			}
		}
	}
	if !sawLowerScheme {
		t.Errorf("expected a canonical url indicator with a lowercased scheme; got %+v", inds)
	}
}

// An IPv6 URL host keeps its mandatory brackets in the canonical url so the value
// stays parseable, and is emitted as a clean (bracketless) ipv6 indicator.
func TestIndicatorsIPv6URLBracketsAndHost(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://[2001:db8::1]:8443/x#frag", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "curl https://[2606:4700:4700::1111]/dns", EventID: "e2"},
	}
	inds := Indicators(events)
	if findInd(inds, IndicatorURL, "https://[2001:db8::1]:8443/x") == nil {
		t.Errorf("IPv6 url must keep brackets and drop fragment; got %+v", inds)
	}
	if findInd(inds, IndicatorIPv6, "2001:db8::1") == nil {
		t.Errorf("clean ipv6 host indicator missing; got %+v", inds)
	}
	if findInd(inds, IndicatorURL, "https://[2606:4700:4700::1111]/dns") == nil {
		t.Errorf("default-port IPv6 url must keep brackets; got %+v", inds)
	}
	if findInd(inds, IndicatorIPv6, "2606:4700:4700::1111") == nil {
		t.Errorf("second ipv6 host missing; got %+v", inds)
	}
}

// Adjacent same-type indicators separated by a single boundary byte must ALL be
// captured — the boundary is asserted without being consumed, so no value after
// the first is lost.
func TestIndicatorsAdjacentSameType(t *testing.T) {
	h1 := "d41d8cd98f00b204e9800998ecf8427e"
	h2 := "5d41402abc4b2a76b9719d911017c592"
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "ips 8.8.8.8 9.9.9.9", EventID: "e1"},
		{EventType: model.EventCommandExec, Command: "more 1.1.1.1,8.8.4.4", EventID: "e2"},
		{EventType: model.EventMessageAssistant, ContentPreview: h1 + " " + h2, EventID: "e3"},
	}
	inds := Indicators(events)
	for _, want := range []string{"8.8.8.8", "9.9.9.9", "1.1.1.1", "8.8.4.4"} {
		if findInd(inds, IndicatorIPv4, want) == nil {
			t.Errorf("ipv4 %s missing (adjacent indicator dropped); got %+v", want, inds)
		}
	}
	if findInd(inds, IndicatorMD5, h1) == nil || findInd(inds, IndicatorMD5, h2) == nil {
		t.Errorf("both adjacent md5 hashes must be captured; got %+v", inds)
	}
}

// A 64-char digest abutting more hex (a slice of a longer blob) is matched whole
// and rejected by length, never clipped to its first 32 chars.
func TestIndicatorsHashLengthBoundaries(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	events := []model.Event{
		{EventType: model.EventCommandExec, Command: "sum " + sha256, EventID: "e1"},
		// A 65-char hex run is not a valid hash length: drop, don't clip to 32/64.
		{EventType: model.EventCommandExec, Command: "blob " + sha256 + "a", EventID: "e2"},
	}
	inds := Indicators(events)
	if findInd(inds, IndicatorSHA256, sha256) == nil {
		t.Errorf("sha256 missing; got %+v", inds)
	}
	if findInd(inds, IndicatorMD5, sha256[:32]) != nil {
		t.Errorf("64-char digest must not be clipped to a 32-char md5; got %+v", inds)
	}
}

// Defanged threat-report spellings (hxxp, [.], (.), [@]) are refanged before
// extraction so the indicators are recognized and emitted in canonical form.
func TestIndicatorsRefangsDefangedIndicators(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventMessageAssistant, ContentPreview: "drop from hxxps://evil[.]example/x", EventID: "e1"},
		{EventType: model.EventMessageAssistant, ContentPreview: "c2 at 1[.]2[.]3[.]4 contact attacker[@]bad[.]example", EventID: "e2"},
	}
	inds := Indicators(events)
	if findInd(inds, IndicatorURL, "https://evil.example/x") == nil {
		t.Errorf("refanged url missing; got %+v", inds)
	}
	if findInd(inds, IndicatorDomain, "evil.example") == nil {
		t.Errorf("refanged domain missing; got %+v", inds)
	}
	if findInd(inds, IndicatorIPv4, "1.2.3.4") == nil {
		t.Errorf("refanged ipv4 missing; got %+v", inds)
	}
	if findInd(inds, IndicatorEmail, "attacker@bad.example") == nil {
		t.Errorf("refanged email missing; got %+v", inds)
	}
}

func TestIndicatorsEmpty(t *testing.T) {
	if inds := Indicators(nil); len(inds) != 0 {
		t.Errorf("nil events should yield no indicators, got %d", len(inds))
	}
}

// The incremental IndicatorAccumulator (fed one event at a time, as the scanner
// does to avoid retaining the stream) must produce byte-identical output to the
// batch Indicators wrapper over the same events.
func TestIndicatorAccumulatorMatchesBatch(t *testing.T) {
	events := []model.Event{
		{EventType: model.EventNetworkIndicator, URL: "https://evil.example/x", EventID: "e1", Timestamp: "2026-06-02T10:00:00Z"},
		{EventType: model.EventCommandExec, Command: "curl http://8.8.8.8/y", EventID: "e2", Timestamp: "2026-06-02T10:00:05Z"},
		{EventType: model.EventMessageAssistant, ContentPreview: "drop d41d8cd98f00b204e9800998ecf8427e", EventID: "e3", Timestamp: "2026-06-02T10:00:03Z"},
	}

	acc := NewIndicatorAccumulator()
	for _, ev := range events {
		acc.Add(ev)
	}
	got := acc.Materialize()
	want := Indicators(events)

	if len(got) != len(want) {
		t.Fatalf("accumulator yielded %d indicators, batch yielded %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("indicator %d: accumulator %+v != batch %+v", i, got[i], want[i])
		}
	}
}

func TestIndicatorAccumulatorDeduplicatesEventID(t *testing.T) {
	acc := NewIndicatorAccumulator()
	ev := model.Event{
		EventID:   "e1",
		Command:   "curl https://repeat.example/path",
		Timestamp: "2026-06-02T10:00:00Z",
	}
	if acc.Add(ev) || acc.Add(ev) {
		t.Fatal("ordinary duplicate event unexpectedly truncated the accumulator")
	}
	for _, ind := range acc.Materialize() {
		if ind.Count != 1 {
			t.Fatalf("duplicate event inflated %s=%s count to %d", ind.Type, ind.Value, ind.Count)
		}
	}
	ev.EventID = "e2"
	acc.Add(ev)
	for _, ind := range acc.Materialize() {
		if ind.Count != 2 {
			t.Fatalf("distinct event did not increment %s=%s count: %d", ind.Type, ind.Value, ind.Count)
		}
	}
}

func TestIndicatorAccumulatorBoundsOneField(t *testing.T) {
	var command strings.Builder
	for i := 0; i < maxExtractedIndicatorsPerField+20; i++ {
		fmt.Fprintf(&command, " https://host-%d.example/path", i)
	}
	acc := NewIndicatorAccumulator()
	if !acc.Add(model.Event{EventID: "e1", Command: command.String()}) {
		t.Fatal("first bounded field did not report truncation")
	}
	if !acc.Truncated() {
		t.Fatal("Truncated = false after candidate limit")
	}
	if got := len(acc.Materialize()); got > maxExtractedIndicatorsPerField {
		t.Fatalf("materialized %d indicators, cap = %d", got, maxExtractedIndicatorsPerField)
	}
	if acc.Add(model.Event{EventID: "e2", Command: command.String()}) {
		t.Fatal("truncation transition should be reported only once")
	}
}
