// Package redact removes secret-like values from strings before they are
// emitted. Numbat parses highly sensitive artifacts, so redaction is applied
// by default to any content that leaves the tool (observed artifact fields —
// commands, file paths, URLs — and content previews). It is deterministic and
// tested so the same input always yields the same masked output.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// Mask is the token substituted for a detected secret.
const Mask = "[redacted]"

// tokenPatterns match well-known, self-describing secret token shapes
// anywhere in a string. They are high-precision and replaced wholesale.
var tokenPatterns = []*regexp.Regexp{
	// AWS access key id.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// GitHub tokens (classic and fine-grained).
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`),
	// Slack tokens.
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	// OpenAI-style keys.
	regexp.MustCompile(`sk-[0-9A-Za-z_-]{20,}`),
	// Private key PEM headers.
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

const secretKeyTerm = `(?i:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)`

var (
	uriSchemePattern               = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://`)
	authorizationCredentialPattern = regexp.MustCompile(
		`(?i)(^|[^A-Za-z0-9_-])((?:proxy-)?authorization["']?\]?[ \t]*[:=][ \t]*["']?(?:basic|bearer)[ \t]+)([A-Za-z0-9._~+/\-]+=*)`,
	)
)

// urlUserinfoMask is valid URL userinfo and cannot be mined as an email local part.
const urlUserinfoMask = "***"

// secretKey matches a secret-looking assignment key (env var, JSON field,
// YAML key). Capture group 1 is the key text as written.
const secretKey = `([A-Za-z0-9_."'-]*` + secretKeyTerm + `[A-Za-z0-9_."'-]*)`

// credentialQueryKeys is the set of URL query-parameter keys that carry
// credential or signature material — the live-auth params a presigned URL
// embeds. It is anchored on exact key spellings common across signed URLs,
// OAuth/OIDC, API-key auth, and password-style params so an emitted observed_url
// cannot leak a usable signature or credential. Matching is by EXACT key
// (case-insensitive) after normalization; a suffix like "mytoken" or "id_token"
// or a prefix like "presignature" is deliberately not a member and is preserved.
var credentialQueryKeys = map[string]struct{}{
	"x-amz-signature":      {},
	"x-amz-credential":     {},
	"x-amz-security-token": {},
	"access_token":         {},
	"refresh_token":        {},
	"token":                {},
	"sig":                  {},
	"signature":            {},
	"api_key":              {},
	"apikey":               {},
	"api-key":              {},
	"password":             {},
	"passwd":               {},
	"pwd":                  {},
	"client_secret":        {},
	"client-secret":        {},
	"client_assertion":     {},
	"client-assertion":     {},
	"auth":                 {},
	"secret":               {},
}

const maxCredentialQueryKeyLen = len("x-amz-security-token")

// String masks exact credential parameters, secret-like assignments, and
// self-identifying token formats. Credential-key matching uses a normalized
// whole-input view rather than trusting URL boundaries; the broader assignment
// patterns are limited to non-URL spans to avoid masking benign query keys such
// as id_token.
func String(s string) string {
	s = maskURLUserinfo(s)
	s = maskAuthorizationCredentials(s)
	s = maskCredentialValues(s)
	var b strings.Builder
	last := 0
	for _, loc := range urlPattern.FindAllStringIndex(s, -1) {
		b.WriteString(maskAssignAll(s[last:loc[0]]))
		b.WriteString(s[loc[0]:loc[1]])
		last = loc[1]
	}
	b.WriteString(maskAssignAll(s[last:]))
	out := b.String()
	for _, p := range tokenPatterns {
		out = p.ReplaceAllString(out, Mask)
	}
	return out
}

func maskAuthorizationCredentials(s string) string {
	return authorizationCredentialPattern.ReplaceAllString(s, "${1}${2}"+Mask)
}

func maskURLUserinfo(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range uriSchemePattern.FindAllStringIndex(s, -1) {
		authorityStart := loc[1]
		if authorityStart < last {
			continue
		}
		authorityEnd := uriAuthorityEnd(s, authorityStart)
		passwordStart, passwordEnd, ok := uriPasswordSpan(s[authorityStart:authorityEnd])
		if !ok {
			continue
		}
		credentialStart := authorityStart + passwordStart
		credentialEnd := authorityStart + passwordEnd
		if credentialStart >= credentialEnd {
			continue
		}
		b.WriteString(s[last:credentialStart])
		b.WriteString(urlUserinfoMask)
		last = credentialEnd
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// uriPasswordSpan finds user:password only when an @ is followed by a valid
// host. Choosing the first such @ preserves @ inside passwords without letting
// a later email address steal the host from an earlier DSN.
func uriPasswordSpan(authority string) (int, int, bool) {
	for search := 0; search < len(authority); {
		rel := strings.IndexByte(authority[search:], '@')
		if rel < 0 {
			return 0, 0, false
		}
		at := search + rel
		hostEnd := at + 1
		for hostEnd < len(authority) && !uriHostTerminator(authority[hostEnd]) {
			hostEnd++
		}
		if validURIHost(authority[at+1 : hostEnd]) {
			colon := strings.IndexByte(authority[:at], ':')
			if colon < 0 || completeHostPortBeforeSeparator(authority[:at]) {
				return 0, 0, false
			}
			return colon + 1, at, colon+1 < at
		}
		search = at + 1
	}
	return 0, 0, false
}

func uriHostTerminator(b byte) bool {
	switch b {
	case ',', ';', '&', '\'', '(', ')', '*', '+', '=':
		return true
	}
	return uriAuthorityTerminator(b)
}

func validURIHost(hostport string) bool {
	if hostport == "" || strings.ContainsRune(hostport, '@') {
		return false
	}
	u, err := url.Parse("scheme://" + hostport)
	return err == nil && u.User == nil && u.Host == hostport && u.Hostname() != ""
}

// completeHostPortBeforeSeparator recognizes "host:port;...@..." prose. The
// dotted/IP host requirement avoids treating an ordinary user:digits password
// as a completed network authority.
func completeHostPortBeforeSeparator(beforeAt string) bool {
	sep := strings.IndexAny(beforeAt, ",;&")
	if sep < 0 {
		return false
	}
	prefix := beforeAt[:sep]
	u, err := url.Parse("scheme://" + prefix)
	if err != nil || u.User != nil || u.Host != prefix || u.Hostname() == "" || u.Port() == "" {
		return false
	}
	host := u.Hostname()
	return strings.ContainsRune(host, '.') || strings.ContainsRune(host, ':')
}

func uriAuthorityEnd(s string, start int) int {
	for start < len(s) && !uriAuthorityTerminator(s[start]) {
		start++
	}
	return start
}

func uriAuthorityTerminator(b byte) bool {
	switch b {
	case '/', '?', '#', '"', '`', '<', '>', '\\', '{', '}', '|', '^':
		return true
	}
	return b <= ' ' || b >= 0x7f
}

// urlPattern matches an http(s) URL substring inside arbitrary text. It is used
// only to fence off URL regions so the broad assignment pass (which would
// clobber a benign param like id_token) runs only on non-URL text. The
// scheme/authority/path run ends at whitespace or a quote/bracket/brace; an
// optional query run is held together through raw query bytes up to a
// newline/quote/bracket/backslash/backtick. It is best-effort: it does NOT
// decide what to redact — the value-driven pass already did — so an imperfect
// span only affects where the (precise) assignment pass is suppressed, never
// whether a credential leaks.
var urlPattern = regexp.MustCompile(`https?://[^\s?"'<>\\` + "`" + `]*` +
	`(?:\?[^"'<>\\` + "`" + `\r\n]*)?`)

// Spaces are not terminators: masking through them avoids exposing a secret tail
// in malformed or deliberately split values. This can conservatively mask prose
// until the next structural delimiter.
const valueTerminators = "&;#\"'`<>\\,\r\n"

// keyBoundaryChar delimits the maximal candidate key in normalized space. Slash
// is intentionally excluded so path segments shaped like token=value are not
// mistaken for query parameters.
func keyBoundaryChar(b byte) bool {
	switch b {
	case '?', '&', ';', '#',
		'"', '\'', '`', '<', '>', '\\', ',', '=':
		return true
	}
	return false
}

// normChar is one byte of the normalized view together with the raw byte span it
// originated from. raw is the index, in the ORIGINAL input, of the first raw byte
// that produced this normalized byte; rawEnd is one past the LAST raw byte it
// consumed. For a literal byte the span is one byte (rawEnd == raw+1); for a
// percent-decoded byte the span is the FULL outermost source escape (e.g. `%3d`
// or `%253d`), so rawEnd lands just past the whole escape. We rewrite VALUE spans
// in raw space, so a value that begins at a decoded '=' must start at that '='
// token's rawEnd — the byte after the entire escape — or the mask would land
// inside the escape and leak the secret tail.
type normChar struct {
	b      byte
	raw    int
	rawEnd int
}

// wsMarker lets candidate matching interpret control/space bytes as either
// removable key noise or a soft boundary.
const wsMarker = 0x01

// normalizedView percent-decodes to a fixed point, collapses control/space bytes
// to wsMarker, and lowercases ASCII. The suffix-reduction stack resolves nested
// escapes in amortized linear time while preserving each token's original span.
func normalizedView(s string) []normChar {
	view := make([]normChar, 0, len(s))
	for i := 0; i < len(s); i++ {
		view = append(view, normChar{s[i], i, i + 1})
		view = reducePercentSuffix(view)
	}
	for i := range view {
		if isControlOrSpace(view[i].b) {
			view[i].b = wsMarker
			continue
		}
		view[i].b = lowerASCII(view[i].b)
	}
	return view
}

func reducePercentSuffix(view []normChar) []normChar {
	for len(view) >= 3 {
		loIdx := len(view) - 1
		lo, ok := unhex(view[loIdx].b)
		if !ok {
			return view
		}
		hiIdx := loIdx - 1
		for hiIdx >= 0 && isPercentDecodeNoise(view[hiIdx].b) {
			hiIdx--
		}
		if hiIdx < 0 {
			return view
		}
		hi, ok := unhex(view[hiIdx].b)
		if !ok {
			return view
		}
		percentIdx := hiIdx - 1
		for percentIdx >= 0 && isPercentDecodeNoise(view[percentIdx].b) {
			percentIdx--
		}
		if percentIdx < 0 || view[percentIdx].b != '%' {
			return view
		}
		decoded := normChar{hi<<4 | lo, view[percentIdx].raw, view[loIdx].rawEnd}
		view = append(view[:percentIdx], decoded)
	}
	return view
}

func isPercentDecodeNoise(b byte) bool {
	return b <= 0x1F || b == 0x7F || b == ' '
}

// unhex returns the value of an ASCII hex digit and whether b was one.
func unhex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// lowerASCII lowercases an ASCII letter, leaving every other byte unchanged.
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// maskCredentialValues finds exact credential keys in normalized space and
// rewrites only their corresponding raw value spans.
func maskCredentialValues(s string) string {
	view := normalizedView(s)
	// Collect the raw value spans to mask: [rawValStart, rawValEnd). We compute
	// them from the normalized view, then splice the raw string in one pass.
	type span struct{ start, end int }
	var spans []span
	maskedThrough := 0
	for p := 0; p < len(view); p++ {
		if view[p].b != '=' {
			continue
		}
		start := keyStartNorm(view, p)
		if !candidateIsTarget(view, start, p) {
			continue
		}
		// Locate the raw payload through normalized assignment padding and leading
		// wrappers. This covers literal and encoded whitespace without starting a
		// mask inside a percent escape. Balanced quotes remain readable.
		maskStart, payloadStart := credentialValueStarts(view, p)
		// A later credential assignment may begin inside an earlier value span.
		// Skip it only when its payload is already covered; a quoted payload can
		// begin beyond the earlier span and therefore needs its own mask.
		if view[p].raw < maskedThrough && payloadStart <= maskedThrough {
			continue
		}
		rawValEnd := valueEnd(s, payloadStart)
		spans = append(spans, span{maskSpanStart(s, maskStart, payloadStart, rawValEnd), rawValEnd})
		if rawValEnd > maskedThrough {
			maskedThrough = rawValEnd
		}
	}
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, sp := range spans {
		// spans are produced in increasing order; guard against any overlap from
		// repeated/adjacent keys so we never emit a value byte twice.
		if sp.start < last {
			if sp.end > last {
				last = sp.end
			}
			continue
		}
		b.WriteString(s[last:sp.start])
		b.WriteString(Mask)
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}

func maskSpanStart(s string, maskStart, payloadStart, rawValEnd int) int {
	if payloadStart <= maskStart || maskStart >= len(s) || rawValEnd >= len(s) {
		return maskStart
	}
	switch q := s[maskStart]; q {
	case '"', '\'', '`':
		if s[rawValEnd] == q {
			return payloadStart
		}
	}
	return maskStart
}

func credentialValueStarts(view []normChar, eq int) (maskStart, payloadStart int) {
	i := eq + 1
	for i < len(view) && view[i].b == wsMarker {
		i++
	}
	if i == len(view) {
		return view[len(view)-1].rawEnd, view[len(view)-1].rawEnd
	}
	maskStart = view[i].raw
	for i < len(view) && isLeadingWrapper(view[i].b) {
		i++
	}
	if i == len(view) {
		return maskStart, view[len(view)-1].rawEnd
	}
	return maskStart, view[i].raw
}

func isLeadingWrapper(b byte) bool {
	switch b {
	case '"', '\'', '`', '<', '>', '\\':
		return true
	}
	return false
}

// keyStartNorm returns the start of the maximal candidate before eq. wsMarker is
// not a hard boundary; candidateIsTarget decides how to interpret it.
func keyStartNorm(view []normChar, eq int) int {
	j := eq
	for j > 0 && !keyBoundaryChar(view[j-1].b) {
		j--
	}
	return j
}

// candidateIsTarget tests every contiguous window of wsMarker-delimited
// segments. Markers can therefore act as removable key noise or as boundaries.
// Active windows are capped at the longest supported key, keeping work linear
// in the candidate length with a small fixed factor.
func candidateIsTarget(view []normChar, start, end int) bool {
	if start >= end {
		return false
	}
	type keyCandidate struct {
		bytes [maxCredentialQueryKeyLen]byte
		len   int
	}
	var a, b [maxCredentialQueryKeyLen]keyCandidate
	active, next := &a, &b
	activeN := 0
	for i := start; i < end; {
		for i < end && view[i].b == wsMarker {
			i++
		}
		segmentStart := i
		for i < end && view[i].b != wsMarker {
			i++
		}
		segmentLen := i - segmentStart
		if segmentLen == 0 {
			break
		}
		if segmentLen > maxCredentialQueryKeyLen {
			activeN = 0
			continue
		}

		nextN := 0
		for j := 0; j < activeN; j++ {
			candidate := active[j]
			if candidate.len+segmentLen > maxCredentialQueryKeyLen {
				continue
			}
			for k := segmentStart; k < i; k++ {
				candidate.bytes[candidate.len] = view[k].b
				candidate.len++
			}
			next[nextN] = candidate
			nextN++
		}
		var standalone keyCandidate
		for k := segmentStart; k < i; k++ {
			standalone.bytes[standalone.len] = view[k].b
			standalone.len++
		}
		next[nextN] = standalone
		nextN++
		active, next = next, active
		activeN = nextN

		for j := 0; j < activeN; j++ {
			candidate := &active[j]
			if _, ok := credentialQueryKeys[string(candidate.bytes[:candidate.len])]; ok {
				return true
			}
		}
	}
	return false
}

// valueEnd returns the index one past the end of the credential value that
// begins at start. The value runs to the nearest valueTerminators byte (or end
// of input). Spaces do NOT terminate (see valueTerminators) — there is no
// first-word clamp, so a value produced by an injected space (`token=abc def`)
// is masked in full rather than leaking its tail.
func valueEnd(s string, start int) int {
	i := start
	for i < len(s) && strings.IndexByte(valueTerminators, s[i]) < 0 {
		i++
	}
	return i
}

// maskAssignAll runs every assignment pass over s, masking KEY=VALUE secret
// values while preserving key and quote shape.
func maskAssignAll(s string) string {
	for _, ap := range assignPatterns {
		s = maskAssign(ap, s)
	}
	return s
}

// assignPatterns mask the value of a KEY=VALUE / "key": "value" / key: value
// assignment while preserving the key and surrounding quote/delimiter shape.
var assignPatterns = []assignPattern{
	// Double-quoted value: KEY: "value with spaces" / "key"="value".
	{regexp.MustCompile(secretKey + `(\s*[:=]\s*")([^"]*)(")`), 1, 2, 3, 4},
	// Single-quoted value: KEY='value with spaces'.
	{regexp.MustCompile(secretKey + `(\s*[:=]\s*')([^']*)(')`), 1, 2, 3, 4},
	// Unquoted value: KEY=value / KEY: value (stops at whitespace, comma,
	// or closing brace/bracket so it never eats trailing structure).
	{regexp.MustCompile(secretKey + `(\s*[:=]\s*)([^\s,}\]"']+)()`), 1, 2, 3, 4},
}

// assignPattern pairs a compiled regex with the submatch indices for the key,
// the pre-value text (operator + opening quote), the value, and the post-value
// text (closing quote). A zero post index means "no closing delimiter".
type assignPattern struct {
	re                     *regexp.Regexp
	keyIdx, preIdx, valIdx int
	postIdx                int
}

// maskAssign replaces the value submatch of an assignPattern with Mask, keeping
// the key, separator, and any closing delimiter intact.
func maskAssign(ap assignPattern, s string) string {
	return ap.re.ReplaceAllStringFunc(s, func(m string) string {
		sub := ap.re.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		post := ""
		if ap.postIdx < len(sub) {
			post = sub[ap.postIdx]
		}
		return sub[ap.keyIdx] + sub[ap.preIdx] + Mask + post
	})
}

// isControlOrSpace includes '+' because query strings commonly use it for space.
func isControlOrSpace(b byte) bool {
	return b <= 0x1F || b == 0x7F || b == ' ' || b == '+'
}
