// Package redact removes secret-like values from strings before they are
// emitted. Numbat parses highly sensitive artifacts, so redaction is applied
// by default to any content that leaves the tool (observed artifact fields —
// commands, file paths, URLs — and content previews). It is deterministic and
// tested so the same input always yields the same masked output.
package redact

import (
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

// authorizationBearerPattern matches an RFC 6750 bearer credential in the
// Authorization header position: the literal header name, an optional
// JSON/YAML quote and ':'/'=' operator, the literal Bearer scheme, then the
// credential. Group 1 is the header and scheme text and is preserved; group 2 is
// the credential and is masked, so an observed request stays readable.
//
// Precision boundaries, each chosen to keep this anchored rather than fuzzy:
//   - The header anchor is REQUIRED. RFC 6750 defines the scheme only for this
//     header, so a floating "Bearer" word in prose, a log message, or an
//     identifier is not a credential context and masking after it would be a
//     pure false positive. Matching is case-insensitive (HTTP header names are)
//     and unanchored on the left, which also covers Proxy-Authorization. The
//     header name must be followed directly by the operator, so a subscript or
//     call form (headers["Authorization"] = "Bearer …") is an accepted false
//     negative: admitting one such spelling invites every other quoting and
//     accessor syntax, with no principled place to stop.
//   - The credential charset is b64token plus its optional '=' padding, so a
//     shell placeholder such as `Bearer $TOKEN` or a doc placeholder such as
//     `Bearer <token>` stays readable.
//   - 8 bytes is the minimum credential length. It sits above every short
//     synthetic placeholder ("test", "tok123", "secret" — 4 to 6 bytes) that
//     appears in fixtures and documentation, and below the shortest real token
//     this pass exists to catch. A genuine token under 8 bytes is an accepted
//     false negative. NOTE the length gate is the ONLY filter on the credential:
//     the header anchor is trusted, so a word of prose that follows it ("…the
//     Authorization: Bearer credential must be rotated") is masked too. That is
//     an accepted over-mask — the alternative is entropy or dictionary guessing,
//     which is neither deterministic nor explainable — and the anchor keeps it
//     confined to text that already claims to be an Authorization header.
//   - The separator is SP/HTAB only, not any whitespace. Content previews are
//     multi-line, so crossing a newline would mask the next line's first word;
//     an obs-folded header is therefore an accepted false negative.
var authorizationBearerPattern = regexp.MustCompile(
	`(?i)(authorization["']?[ \t]*[:=][ \t]*["']?bearer[ \t]+)([A-Za-z0-9._~+/-]{8,}={0,2})`)

// secretKey matches a secret-looking assignment key (env var, JSON field,
// YAML key). Capture group 1 is the key text as written.
const secretKey = `([A-Za-z0-9_."'-]*(?i:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)[A-Za-z0-9_."'-]*)`

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

// String masks exact credential parameters, credentials held in a fixed
// grammatical position (a URL userinfo password, an Authorization: Bearer
// credential), secret-like assignments, and self-identifying token formats.
// Credential-key matching uses a normalized whole-input view rather than
// trusting URL boundaries; the broader assignment patterns are limited to
// non-URL spans to avoid masking benign query keys such as id_token.
//
// The position-driven passes run first: they delimit their own credential span
// exactly, so masking there leaves less ambiguous text for the later, broader
// passes to interpret.
func String(s string) string {
	s = maskURLUserinfoPasswords(s)
	s = maskAuthorizationBearer(s)
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
	for p := 0; p < len(view); p++ {
		if view[p].b != '=' {
			continue
		}
		start := keyStartNorm(view, p)
		if !candidateIsTarget(view, start, p) {
			continue
		}
		// The mask begins at the raw END of the '=' token: one past the WHOLE
		// raw escape when the '=' only appears after percent-decoding (`%3d`,
		// `%253d`, deep), or one past a literal '='. Using rawEnd (not raw+1)
		// keeps the mask from starting inside the escape and leaking the secret
		// tail.
		maskStart := view[p].rawEnd
		// payloadStart skips the FULL leading run of wrapper/terminator bytes
		// (quote/bracket/'>') before locating the value run. Balanced quote
		// wrappers are preserved for readability (PASSWORD="[redacted]" stays
		// quoted), but unbalanced wrappers and bracket-like bytes are masked too
		// so token=> cannot leak the lone ">" value.
		payloadStart := skipLeadingWrappers(s, maskStart)
		rawValEnd := valueEnd(s, payloadStart)
		spans = append(spans, span{maskSpanStart(s, maskStart, payloadStart, rawValEnd), rawValEnd})
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

// skipLeadingWrappers advances over a full quote/bracket/escape run so masking
// cannot stop before the actual value.
func skipLeadingWrappers(s string, pos int) int {
	for pos < len(s) {
		switch s[pos] {
		case '"', '\'', '`', '<', '>', '\\':
			pos++
		default:
			return pos
		}
	}
	return pos
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

// urlSchemePattern matches an RFC 3986 scheme followed by "//": the start of a
// URL authority. It deliberately accepts ANY scheme rather than just http(s),
// because an embedded password is overwhelmingly a database or broker DSN
// (postgres://, redis://, amqp://, mongodb+srv://), and a defanged scheme
// (hxxp://) must still be recognized. It only locates a candidate authority;
// maskURLUserinfoPasswords decides what to mask. Note this is NOT urlPattern:
// widening that pattern would extend the region where the assignment pass is
// suppressed, which changes unrelated behavior.
var urlSchemePattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://`)

// userinfoMask replaces a URL password in place. It is Mask with its brackets
// percent-encoded, because the emitted URL must remain parseable: downstream
// consumers strip userinfo structurally with net/url, and a raw "[redacted]" is
// invalid userinfo, so it would fail that parse and drop the whole URL — host and
// path included — rather than just the credential.
const userinfoMask = "%5Bredacted%5D"

// maskURLUserinfoPasswords masks the password of a URL authority
// (scheme://user:password@host). The credential is identified by its POSITION in
// the RFC 3986 grammar, not by a secret-looking key name, which is what closes
// the DSN leak class (postgres://user:p4ssw0rd@host/db): no query key, no
// assignment key, and no self-describing shape is present for the other passes
// to match. The username, host, port, and path are left intact by THIS pass —
// they carry triage value and are not credentials. (A username that is itself
// secret-looking, as in postgres://token:pw@host/db, is still masked by the later
// assignment pass, which takes the rest of the URL with it.)
//
// Span boundaries — both are load-bearing, and TestStringMasksURLUserinfoPassword
// asserts exact output because a substring check cannot tell them apart:
//   - The userinfo ends at the LAST '@' inside the authority, so neither a
//     password containing '@' nor a later '@' in the path or query can leave a
//     surviving credential tail.
//   - The password starts at the FIRST ':' of the userinfo, so a password
//     containing ':' is masked whole.
//
// Not masked, by design:
//   - A userinfo with no ':' (scheme://token@host): a bare username is normally
//     not a credential, and a self-describing token there is already caught by
//     tokenPatterns. An empty password (scheme://user:@host) has nothing to leak.
//   - A userinfo holding a byte that ends the authority scan — an unencoded '/',
//     whitespace, a non-ASCII byte, a quote, or one of the list separators in
//     authorityTerminator. This covers the USERNAME as well as the password: the
//     scan stops before it ever reaches the '@', so postgres://usér:pw@h/db is
//     left alone even though the password itself is maskable. The scan then finds
//     no '@' and masks nothing, so every case here is a false negative rather
//     than a partial mask, and each class is recorded in
//     TestStringKnownFalseNegatives. Widening the scan to recover them was
//     measured to be worse: it reads a benign path such as /download/file@2x.png
//     as userinfo and masks the path, and running through non-ASCII text lets a
//     CJK sentence bridge a host:port to an address later in the line.
func maskURLUserinfoPasswords(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range urlSchemePattern.FindAllStringIndex(s, -1) {
		authStart := loc[1]
		// Matches arrive in increasing order and authorityEnd stops at the '/'
		// that any later scheme match must contain, so spans cannot overlap and
		// this cannot fire today. It stays because the splice below indexes
		// s[last:pwStart]: were that invariant ever broken, the alternative to
		// skipping is a panic on a redaction path.
		if authStart < last {
			continue
		}
		at := strings.LastIndexByte(s[authStart:authorityEnd(s, authStart)], '@')
		if at < 0 {
			continue
		}
		colon := strings.IndexByte(s[authStart:authStart+at], ':')
		if colon < 0 {
			continue
		}
		pwStart, pwEnd := authStart+colon+1, authStart+at
		if pwStart >= pwEnd {
			continue
		}
		if last == 0 {
			b.Grow(len(s) + len(userinfoMask))
		}
		b.WriteString(s[last:pwStart])
		b.WriteString(userinfoMask)
		last = pwEnd
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// authorityEnd returns the index one past the URL authority beginning at start.
// The scan is deliberately short rather than greedy, because every byte it reads
// past the real host is a byte that can turn an unrelated '@' later in the line
// into a fabricated userinfo — masking a port as a password, destroying two true
// indicators and inventing a third. It therefore stops at:
//
//   - '/', '?', '#' — where RFC 3986 ends the authority.
//   - Whitespace, control bytes, the quote/brace/pipe wrappers, and every
//     non-ASCII byte, none of which may appear in a URI at all. A URI is ASCII,
//     so a byte >= 0x80 is the text AROUND the URL — CJK or other non-English
//     prose, a no-break space pasted from a page, typographic punctuation — and
//     treating it as authority-legal is how a CJK sentence bridges a benign
//     host:port to an address later in the line. Stopping at a wrapper also keeps
//     the scan inside one quoted string, so a JSON value like "redis://u:p"
//     followed by a later field containing '@' is not read as a single authority.
//   - ',' ';' '&' '(' ')' — legal userinfo sub-delims, but in practice they
//     separate items in a list, a query, or a CSV row and wrap a markdown link.
//     Reading past one is exactly how "https://api.test:8443;user=ops@corp.test"
//     becomes a false positive, so precision wins here.
//
// The cost is a false negative when a password contains one of those bytes
// unencoded (RFC 3986 requires percent-encoding for all of them except the five
// sub-delims); see maskURLUserinfoPasswords and TestStringKnownFalseNegatives.
func authorityEnd(s string, start int) int {
	i := start
	for i < len(s) && !authorityTerminator(s[i]) {
		i++
	}
	return i
}

// authorityTerminator reports whether b ends an authority scan. '[' and ']' are
// deliberately absent so an IPv6 literal host stays inside the scan.
func authorityTerminator(b byte) bool {
	switch b {
	case '/', '?', '#',
		'"', '\'', '`', '<', '>', '\\', '{', '}', '|', '^',
		',', ';', '&', '(', ')':
		return true
	}
	// Space, every control byte, and every non-ASCII byte (DEL upward).
	return b <= ' ' || b >= 0x7F
}

// maskAuthorizationBearer masks the credential of an Authorization: Bearer
// header, keeping the header name and scheme so the observed request stays
// readable. See authorizationBearerPattern for the precision boundaries.
func maskAuthorizationBearer(s string) string {
	return authorizationBearerPattern.ReplaceAllString(s, "${1}"+Mask)
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
