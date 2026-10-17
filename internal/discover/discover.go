// Package discover locates agent artifacts on disk and classifies each by the
// agent that produced it. It is the filesystem-facing counterpart to package
// extract: discover walks directories and stats files, extract parses the bytes
// of a single artifact. Keeping the two apart lets parsers stay pure and lets
// discovery evolve (new agents, new default locations) without touching them.
package discover

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// errNotRegular marks a path that classified as an artifact but is not a regular
// file (a FIFO, socket, or device). Such a file is skipped rather than opened,
// since reading a pipe or device can block a scan indefinitely.
var errNotRegular = errors.New("not a regular file")

// Artifact is one discovered on-disk file together with the agent it belongs
// to. Path is absolute when the scanned root is absolute.
type Artifact struct {
	// Path is the artifact's location on disk.
	Path string
	// Agent is the model.Agent* identifier of the producing agent, chosen by
	// where the file lives and what it is named.
	Agent string
	// readPath is the resolved, validated path opened by OpenArtifact. Path stays
	// unchanged so evidence points to the location the operator scanned.
	readPath string
}

// DedupeKey identifies the physical file an artifact will open. Scan and
// timeline use it to avoid processing a file twice when requested roots repeat,
// overlap, or reach the same file through a symlink.
func (a Artifact) DedupeKey() string {
	path := a.readPath
	if path == "" {
		path = a.Path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return pathIdentity(filepath.Clean(path))
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return pathIdentity(filepath.Clean(abs))
}

// Skip records a subtree that could not be read during a walk. Discovery never
// aborts on an unreadable subtree, but for a forensic scan a coverage gap is
// itself a finding: the caller surfaces each Skip as a diagnostic so absent
// evidence is visible rather than silent.
type Skip struct {
	// Path is the entry that could not be read.
	Path string
	// Err is the access error that caused the subtree to be skipped.
	Err error
}

// Default roots and path markers for parser-backed agents. Root markers keep
// one agent's bookkeeping files from falling through to another JSON parser.
const claudeProjectsDir = ".claude/projects"

const (
	geminiTmpDir     = ".gemini/tmp"
	geminiRootMarker = ".gemini"
)

const (
	geminiLogsFile         = "logs.json"
	geminiCheckpointPrefix = "checkpoint-"
	geminiChatsDir         = "chats"
)

const (
	coworkMacSessionsDir = "Library/Application Support/Claude/local-agent-mode-sessions"
	coworkPathMarker     = "local-agent-mode-sessions"
)

const (
	claudeHistoryFile = ".claude/history.jsonl"
	codexHistoryFile  = ".codex/history.jsonl"
)

const (
	cursorProjectsDir = ".cursor/projects"
	cursorPathMarker  = "agent-transcripts"
)

const (
	windsurfTranscriptsDir = ".windsurf/transcripts"
	windsurfPathMarker     = ".windsurf/transcripts"
	windsurfRootMarker     = ".windsurf"
)

const (
	copilotPathMarker = ".copilot/session-state"
	copilotEventsFile = "events.jsonl"
	copilotRootMarker = ".copilot"
)

// OpenCode's earlier file stores use one JSON object per record. Current
// releases may use opencode.db, which numbat does not classify as an artifact.
const (
	opencodeDataDir       = ".local/share/opencode"
	opencodeStorageMarker = "opencode/storage"
)

const (
	openclawAgentsSegment    = "agents"
	openclawSessionsSegment  = "sessions"
	openclawAgentSegment     = "agent"
	openclawCodexHomeSegment = "codex-home"
	openclawRootMarker       = ".openclaw"
	openclawLegacyRootMarker = ".clawdbot"
)

var (
	// Stable retained archives are complete session transcripts. OpenClaw's own
	// corpus indexes reset/deleted variants. Backup rotations and compaction
	// checkpoints are intentionally not in this set because OpenClaw treats them
	// as opaque duplicate snapshots.
	openClawRetainedArchiveRE = regexp.MustCompile(`^.+\.jsonl\.(?:reset|deleted)\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:\.\d{3})?Z$`)
	openClawCheckpointRE      = regexp.MustCompile(`(?i)^.+\.checkpoint\.[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.jsonl$`)
)

const piSessionsDir = ".pi/agent/sessions"

const (
	kimiCodeHomeDir  = ".kimi-code"
	kimiSessionsDir  = ".kimi-code/sessions"
	kimiWireFileName = "wire.jsonl"
)

const (
	museSessionFileName = "session.jsonl"
	// subagentDirName holds one full transcript per spawned subagent, nested
	// under its parent's own session directory. Not a Muse-specific concept in
	// this package (Kimi's subagent layout uses a plain "agents" segment
	// instead), so it is scoped to the Muse helpers with this name.
	subagentDirName = "subagent"
)

// DefaultRoots returns all existing parser-backed artifact roots. It honors
// agent-specific home overrides and XDG_DATA_HOME.
func DefaultRoots(home string) []string {
	return DefaultRootsFor(home, nil)
}

// DefaultRootsFor returns existing parser-backed artifact roots for the
// requested model.Agent* identifiers. An empty agents slice selects all agents.
func DefaultRootsFor(home string, agents []string) []string {
	var roots []string
	seen := map[string]struct{}{}
	selectedAgents := make(map[string]struct{}, len(agents))
	for _, agent := range agents {
		selectedAgents[agent] = struct{}{}
	}
	selected := func(agent string) bool {
		if len(selectedAgents) == 0 {
			return true
		}
		_, ok := selectedAgents[agent]
		return ok
	}
	addDir := func(paths ...string) {
		for _, p := range paths {
			addExisting(&roots, seen, p, dirExists)
		}
	}
	addFile := func(paths ...string) {
		for _, p := range paths {
			addExisting(&roots, seen, p, fileExists)
		}
	}

	if selected(model.AgentClaudeCode) {
		addDir(claudeRootCandidates(home, "projects")...)
	}
	if selected(model.AgentGeminiCLI) {
		addDir(geminiRootCandidates(home, "tmp")...)
	}
	if selected(model.AgentCodex) {
		addDir(codexRootCandidates(home, "sessions")...)
		addDir(codexRootCandidates(home, "archived_sessions")...)
	}
	if selected(model.AgentCowork) {
		addDir(CoworkRootCandidates(home)...)
	}
	if selected(model.AgentCursor) {
		addDir(filepath.Join(home, cursorProjectsDir))
	}
	if selected(model.AgentWindsurf) {
		addDir(filepath.Join(home, windsurfTranscriptsDir))
	}
	if selected(model.AgentCopilot) {
		addDir(copilotRootCandidates(home, "session-state")...)
	}
	if selected(model.AgentOpenCode) {
		addDir(opencodeStorageCandidates(home)...)
	}
	if selected(model.AgentOpenClaw) {
		addDir(OpenClawRootCandidates(home)...)
	}
	if selected(model.AgentPi) {
		addDir(PiRootCandidates(home)...)
	}
	if selected(model.AgentKimiCode) {
		addDir(KimiCodeRootCandidates(home)...)
	}
	if selected(model.AgentMuseCode) {
		addDir(MuseSessionsRootCandidates(home)...)
	}

	// The prompt-history files live at the agent roots, outside the session
	// trees above, so each joins as its own single-file root.
	if selected(model.AgentClaudeCode) {
		addFile(claudeRootCandidates(home, "history.jsonl")...)
	}
	if selected(model.AgentCodex) {
		addFile(codexRootCandidates(home, "history.jsonl")...)
	}
	return roots
}

func addExisting(out *[]string, seen map[string]struct{}, path string, exists func(string) bool) {
	if path == "" || !exists(path) {
		return
	}
	clean := filepath.Clean(path)
	key := clean
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		key = filepath.Clean(resolved)
	}
	key = pathIdentity(key)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, clean)
}

func codexRootCandidates(home, rel string) []string {
	return rootOverrideCandidates(home, ".codex", "CODEX_HOME", rel)
}

func claudeRootCandidates(home, rel string) []string {
	return rootOverrideCandidates(home, ".claude", "CLAUDE_CONFIG_DIR", rel)
}

func geminiRootCandidates(home, rel string) []string {
	var paths []string
	if override := os.Getenv("GEMINI_CLI_HOME"); override != "" {
		paths = append(paths, filepath.Join(override, ".gemini", rel))
	}
	return append(paths, filepath.Join(home, ".gemini", rel))
}

func copilotRootCandidates(home, rel string) []string {
	return rootOverrideCandidates(home, ".copilot", "COPILOT_HOME", rel)
}

func rootOverrideCandidates(home, homeRelRoot, envName, rel string) []string {
	var paths []string
	if root := os.Getenv(envName); root != "" {
		paths = append(paths, filepath.Join(root, rel))
	}
	return append(paths, filepath.Join(home, homeRelRoot, rel))
}

func opencodeStorageCandidates(home string) []string {
	var paths []string
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		paths = append(paths,
			filepath.Join(dataHome, "opencode", "storage"),
			filepath.Join(dataHome, "opencode", "project"),
		)
	}
	root := filepath.Join(home, opencodeDataDir)
	return append(paths, filepath.Join(root, "storage"), filepath.Join(root, "project"))
}

// OpenClawRootCandidates returns the one effective agent root selected by
// OpenClaw's state-directory precedence. OPENCLAW_STATE_DIR is authoritative;
// otherwise OPENCLAW_HOME replaces the OS home used for the default. OpenClaw's
// --profile flag projects a concrete OPENCLAW_STATE_DIR inside its process;
// OPENCLAW_PROFILE alone does not select a root. The existing pre-rebrand
// .clawdbot root remains OpenClaw's fallback only when the newer .openclaw root
// does not exist.
func OpenClawRootCandidates(home string) []string {
	return []string{filepath.Join(openClawStateRoot(home), openclawAgentsSegment)}
}

func openClawStateRoot(home string) string {
	effectiveHome := openClawEffectiveHome(home)
	if state := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")); state != "" {
		return resolveOpenClawPath(state, effectiveHome)
	}
	current := filepath.Join(effectiveHome, openclawRootMarker)
	if pathExists(current) {
		return current
	}
	legacy := filepath.Join(effectiveHome, openclawLegacyRootMarker)
	if pathExists(legacy) {
		return legacy
	}
	return current
}

func validOpenClawProfile(profile string) bool {
	if len(profile) == 0 || len(profile) > 64 || !isASCIIAlphaNumeric(rune(profile[0])) {
		return false
	}
	for _, r := range profile[1:] {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func isASCIIAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

func openClawEffectiveHome(home string) string {
	root := strings.TrimSpace(os.Getenv("OPENCLAW_HOME"))
	if root == "" || root == "undefined" || root == "null" {
		return filepath.Clean(home)
	}
	return resolveOpenClawPath(root, home)
}

func resolveOpenClawPath(root, tildeHome string) string {
	switch {
	case root == "~":
		root = tildeHome
	case strings.HasPrefix(root, "~/") || strings.HasPrefix(root, `~\`):
		root = filepath.Join(tildeHome, root[2:])
	}
	if absolute, err := filepath.Abs(root); err == nil {
		return filepath.Clean(absolute)
	}
	return filepath.Clean(root)
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// PiRootCandidates returns Pi's effective session store. The environment
// variable names the session directory itself (unlike CODEX_HOME, which names
// an agent root), so it is not joined with another path component.
func PiRootCandidates(home string) []string {
	var paths []string
	if root := os.Getenv("PI_CODING_AGENT_SESSION_DIR"); root != "" {
		paths = append(paths, root)
	}
	if root := os.Getenv("PI_CODING_AGENT_DIR"); root != "" {
		paths = append(paths, filepath.Join(root, "sessions"))
	}
	return append(paths, filepath.Join(home, piSessionsDir))
}

// KimiCodeRootCandidates returns the current Kimi Code session root. Legacy
// kimi-cli used a different home and record language and is intentionally not
// mixed into this classifier.
func KimiCodeRootCandidates(home string) []string {
	return rootOverrideCandidates(home, kimiCodeHomeDir, "KIMI_CODE_HOME", "sessions")
}

// MuseSessionsRootCandidates returns Muse Code's session store root(s). Muse is
// an XDG-conformant application (confirmed against the installed binary and by
// pointing XDG_DATA_HOME at a scratch directory): XDG_DATA_HOME wins when set,
// otherwise the store lives at ~/.local/share/muse/sessions.
func MuseSessionsRootCandidates(home string) []string {
	var paths []string
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		paths = append(paths, filepath.Join(dataHome, "muse", "sessions"))
	}
	return append(paths, filepath.Join(home, ".local", "share", "muse", "sessions"))
}

// CoworkRootCandidates returns local Cowork audit roots verified with parser
// fixtures. Native Windows and Linux stores remain explicit --path inputs until
// their current locations and record formats are captured.
func CoworkRootCandidates(home string) []string {
	return coworkRootCandidates(runtime.GOOS, home)
}

func coworkRootCandidates(goos, home string) []string {
	if goos == "darwin" {
		return []string{filepath.Join(home, coworkMacSessionsDir)}
	}
	return nil
}

// Walk returns the artifacts found under root in deterministic (lexical) order,
// along with any subtrees that could not be read. root may be a single file
// (returned as one artifact if it classifies) or a directory (walked
// recursively). Unreadable subtrees are skipped rather than aborting the walk,
// because a forensic target often has paths the scanning user cannot fully
// read; each skip is reported so the gap is visible, and an error is returned
// only when root itself cannot be accessed.
//
// A symlinked directory root is resolved before walking: os.Stat follows the
// link and reports a directory, but filepath.WalkDir would treat the link as a
// leaf and descend no further. Resolving the target ensures a symlinked root
// (a relocated ~/.claude, a mounted image, a dotfile-managed home) is scanned
// instead of silently yielding nothing.
func Walk(root string) ([]Artifact, []Skip, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		if a, ok := classify(root); ok {
			// A FIFO, socket, or device file named like an artifact must not be
			// opened: read can block forever on a pipe/device, hanging a scan. Only
			// a regular file is a real artifact; a special one is recorded as a skip
			// so the gap is visible rather than silently parsed. os.Stat follows a
			// symlink, so a symlinked regular artifact still reports regular here.
			if isSpecialFile(info.Mode()) {
				return nil, []Skip{{Path: root, Err: errNotRegular}}, nil
			}
			readPath := root
			if linfo, lerr := os.Lstat(root); lerr != nil {
				return nil, nil, lerr
			} else if linfo.Mode()&fs.ModeSymlink != 0 {
				readPath, err = filepath.EvalSymlinks(root)
				if err != nil {
					return nil, nil, err
				}
			}
			a.readPath = readPath
			return []Artifact{a}, nil, nil
		}
		return nil, nil, nil
	}

	walkRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	if target, err := filepath.EvalSymlinks(walkRoot); err == nil {
		walkRoot = target
	}

	var (
		arts  []Artifact
		skips []Skip
	)
	// Entry errors become diagnostics so one unreadable subtree does not abort
	// the rest of a forensic scan.
	walkErr := filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		logicalPath := logicalWalkPath(root, walkRoot, path)
		if err != nil {
			skips = append(skips, Skip{Path: logicalPath, Err: err})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if a, ok := classify(logicalPath); ok {
			readPath, regular, targetErr := regularArtifactTarget(path, d.Type(), walkRoot)
			if targetErr != nil {
				skips = append(skips, Skip{Path: logicalPath, Err: targetErr})
				return nil
			}
			if !regular {
				skips = append(skips, Skip{Path: logicalPath, Err: errNotRegular})
				return nil
			}
			a.readPath = readPath
			arts = append(arts, a)
		}
		return nil
	})
	if walkErr != nil {
		return arts, skips, walkErr
	}
	return arts, skips, nil
}

func logicalWalkPath(root, walkRoot, path string) string {
	rel, err := filepath.Rel(walkRoot, path)
	if err != nil || rel == "." {
		return root
	}
	return filepath.Join(root, rel)
}

// classify maps a recognized path shape to its parser. A bare JSONL falls back
// to Claude only after known agent roots and bookkeeping files are excluded.
func classify(path string) (Artifact, bool) {
	if isCodexArtifact(path) || isCodexHistoryFile(path) {
		return Artifact{Path: path, Agent: model.AgentCodex}, true
	}
	if isGeminiArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentGeminiCLI}, true
	}
	if isCoworkArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentCowork}, true
	}
	if isCursorArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentCursor}, true
	}
	if isWindsurfArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentWindsurf}, true
	}
	if isCopilotArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentCopilot}, true
	}
	if isOpenCodeArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentOpenCode}, true
	}
	if isOpenClawArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentOpenClaw}, true
	}
	if isPiArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentPi}, true
	}
	if isKimiCodeArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentKimiCode}, true
	}
	if isMuseCodeArtifact(path) {
		return Artifact{Path: path, Agent: model.AgentMuseCode}, true
	}
	if strings.EqualFold(filepath.Ext(path), ".jsonl") {
		if underCursorProjects(path) || underWindsurfRoot(path) ||
			underCopilotRoot(path) || underGeminiRoot(path) ||
			underOpenClawRoot(path) || underPiRoot(path) || underKimiCodeRoot(path) || underCodexRoot(path) ||
			underMuseCodeRoot(path) || isClaudeInternalWorkflowJournal(path) {
			return Artifact{}, false
		}
		return Artifact{Path: path, Agent: model.AgentClaudeCode}, true
	}
	return Artifact{}, false
}

// isHistoryFile matches an agent-root history file in absolute or relative form.
func isHistoryFile(path, marker string) bool {
	slashed := slashIdentity(path)
	return strings.HasSuffix(slashed, "/"+marker) || slashed == marker
}

func isCodexHistoryFile(path string) bool {
	if isHistoryFile(path, codexHistoryFile) {
		return true
	}
	root := os.Getenv("CODEX_HOME")
	return root != "" && samePath(path, filepath.Join(root, "history.jsonl"))
}

func underCodexRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/.codex/") ||
		strings.HasPrefix(slashed, ".codex/") ||
		underConfiguredRoot(path, "CODEX_HOME")
}

func underCursorProjects(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+cursorProjectsDir+"/") ||
		strings.HasPrefix(slashed, cursorProjectsDir+"/")
}

// Claude workflow journals share the transcript extension but not its schema.
func isClaudeInternalWorkflowJournal(path string) bool {
	if !strings.EqualFold(filepath.Base(path), "journal.jsonl") {
		return false
	}
	slashed := slashIdentity(path)
	underProjects := strings.Contains(slashed, "/"+claudeProjectsDir+"/") ||
		strings.HasPrefix(slashed, claudeProjectsDir+"/") ||
		underConfiguredSubtree(path, "CLAUDE_CONFIG_DIR", "projects")
	return underProjects && strings.Contains(slashed, "/subagents/workflows/")
}

// isCoworkArtifact matches JSONL below local-agent-mode-sessions.
func isCoworkArtifact(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return false
	}
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+coworkPathMarker+"/") ||
		strings.HasPrefix(slashed, coworkPathMarker+"/")
}

// isCursorArtifact matches JSONL below an agent-transcripts subtree.
func isCursorArtifact(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return false
	}
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+cursorPathMarker+"/") ||
		strings.HasPrefix(slashed, cursorPathMarker+"/")
}

// isWindsurfArtifact matches JSONL below .windsurf/transcripts.
func isWindsurfArtifact(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return false
	}
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+windsurfPathMarker+"/") ||
		strings.HasPrefix(slashed, windsurfPathMarker+"/")
}

func underWindsurfRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+windsurfRootMarker+"/") ||
		strings.HasPrefix(slashed, windsurfRootMarker+"/")
}

// isCopilotArtifact accepts only session-state events.jsonl, not sibling plans
// or checkpoints.
func isCopilotArtifact(path string) bool {
	if !strings.EqualFold(filepath.Base(path), copilotEventsFile) {
		return false
	}
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+copilotPathMarker+"/") ||
		strings.HasPrefix(slashed, copilotPathMarker+"/") ||
		underConfiguredSubtree(path, "COPILOT_HOME", "session-state")
}

func underCopilotRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+copilotRootMarker+"/") ||
		strings.HasPrefix(slashed, copilotRootMarker+"/") ||
		underConfiguredRoot(path, "COPILOT_HOME")
}

// isCodexArtifact matches plain or zstd rollouts in active/archived sessions.
func isCodexArtifact(path string) bool {
	slashed := slashIdentity(path)
	under := strings.Contains(slashed, "/.codex/sessions/") ||
		strings.HasPrefix(slashed, ".codex/sessions/") ||
		strings.Contains(slashed, "/.codex/archived_sessions/") ||
		strings.HasPrefix(slashed, ".codex/archived_sessions/") ||
		underConfiguredSubtree(path, "CODEX_HOME", "sessions", "archived_sessions")
	if !under {
		return false
	}
	lower := strings.ToLower(slashed)
	return strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".jsonl.zst")
}

// isGeminiArtifact accepts current/legacy session records under chats plus the
// older prompt log and manual checkpoint formats below tmp.
func isGeminiArtifact(path string) bool {
	if !underGeminiTmp(path) {
		return false
	}
	if isGeminiSessionArtifact(path) {
		return true
	}
	return isGeminiTranscriptName(filepath.Base(path))
}

func underGeminiTmp(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+geminiTmpDir+"/") ||
		strings.HasPrefix(slashed, geminiTmpDir+"/")
}

func isGeminiSessionArtifact(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".jsonl" && ext != ".json" {
		return false
	}
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+geminiChatsDir+"/")
}

func isGeminiTranscriptName(base string) bool {
	if strings.EqualFold(base, geminiLogsFile) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(base), geminiCheckpointPrefix) &&
		strings.EqualFold(filepath.Ext(base), ".json")
}

func underGeminiRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+geminiRootMarker+"/") ||
		strings.HasPrefix(slashed, geminiRootMarker+"/")
}

// isOpenCodeArtifact matches message and part records in both retained JSON
// layouts: opencode/storage and the older opencode/project/<project>/storage.
func isOpenCodeArtifact(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return false
	}
	segments := strings.Split(slashIdentity(path), "/")
	for i, segment := range segments {
		if segment != "opencode" || i+1 >= len(segments) {
			continue
		}
		if segments[i+1] == "storage" && isOpenCodeRecordTail(segments[i+2:]) {
			return true
		}
		if segments[i+1] == "project" && i+3 < len(segments) &&
			segments[i+2] != "" && segments[i+3] == "storage" {
			return isOpenCodeRecordTail(segments[i+4:])
		}
	}
	return false
}

func isOpenCodeRecordTail(segments []string) bool {
	if len(segments) < 2 {
		return false
	}
	if segments[0] == "part" || segments[0] == "message" {
		return true
	}
	return len(segments) >= 3 && segments[0] == "session" &&
		(segments[1] == "part" || segments[1] == "message")
}

// isOpenClawArtifact validates OpenClaw's three session layouts rather than a
// loose sessions substring: direct Gateway sessions, embedded agent sessions
// partitioned by encoded cwd, and embedded Codex rollouts partitioned by date.
// Historical direct-file variants of both embedded roots remain readable.
func isOpenClawArtifact(path string) bool {
	if !isOpenClawTranscriptFileName(filepath.Base(path)) {
		return false
	}
	segs := strings.Split(slashIdentity(path), "/")
	for agentsIndex := 0; agentsIndex+3 < len(segs); agentsIndex++ {
		if segs[agentsIndex] != openclawAgentsSegment || segs[agentsIndex+1] == "" {
			continue
		}
		if validOpenClawSessionTail(segs[agentsIndex+2:]) && openClawAgentsRoot(segs[:agentsIndex]) {
			return true
		}
	}
	return false
}

func isOpenClawTranscriptFileName(name string) bool {
	if isOpenClawRetainedArchiveName(name) {
		return true
	}
	if !strings.EqualFold(filepath.Ext(name), ".jsonl") {
		return false
	}
	lower := strings.ToLower(name)
	return !strings.HasSuffix(lower, ".trajectory.jsonl") &&
		!openClawCheckpointRE.MatchString(name)
}

func isOpenClawRetainedArchiveName(name string) bool {
	return openClawRetainedArchiveRE.MatchString(name)
}

func validOpenClawSessionTail(tail []string) bool {
	for _, segment := range tail {
		if segment == "" {
			return false
		}
	}
	switch {
	case len(tail) == 2 && tail[0] == openclawSessionsSegment:
		return true
	case len(tail) == 3 && tail[0] == openclawAgentSegment && tail[1] == openclawSessionsSegment:
		return true
	case len(tail) == 4 && tail[0] == openclawAgentSegment && tail[1] == openclawSessionsSegment:
		return true
	case len(tail) == 4 && tail[0] == openclawAgentSegment && tail[1] == openclawCodexHomeSegment && tail[2] == openclawSessionsSegment:
		return true
	case len(tail) == 7 && tail[0] == openclawAgentSegment && tail[1] == openclawCodexHomeSegment && tail[2] == openclawSessionsSegment:
		return validOpenClawCodexDate(tail[3], tail[4], tail[5])
	default:
		return false
	}
}

// validOpenClawCodexDate validates the embedded Codex rollout partition. Stable
// OpenClaw delegates this store to Codex's YYYY/MM/DD layout; accepting any
// three arbitrary directories would misclassify unrelated JSONL as a rollout.
func validOpenClawCodexDate(year, month, day string) bool {
	if len(year) != 4 || len(month) != 2 || len(day) != 2 {
		return false
	}
	_, err := time.Parse("2006/01/02", year+"/"+month+"/"+day)
	return err == nil
}

func openClawAgentsRoot(prefix []string) bool {
	if len(prefix) == 0 {
		return false
	}
	last := prefix[len(prefix)-1]
	return isOpenClawStateRootSegment(last) ||
		configuredOpenClawStateRoot(prefix)
}

func isOpenClawStateRootSegment(segment string) bool {
	if segment == openclawRootMarker || segment == openclawLegacyRootMarker {
		return true
	}
	profile, ok := strings.CutPrefix(segment, openclawRootMarker+"-")
	return ok && !strings.EqualFold(profile, "default") && validOpenClawProfile(profile)
}

// configuredOpenClawStateRoot verifies that the agents segment is an immediate
// child of OPENCLAW_STATE_DIR. Checking only whether path is somewhere below
// the configured directory would incorrectly admit nested lookalike trees such
// as OPENCLAW_STATE_DIR/cache/agents/<id>/sessions/<file>.
func configuredOpenClawStateRoot(prefix []string) bool {
	root := configuredOpenClawStateDir()
	if root == "" {
		return false
	}
	candidate := strings.Join(prefix, "/")
	// Splitting a filesystem root drops its trailing slash ("/" becomes [""]
	// and "C:/" becomes ["c:"]). Restore it before converting back.
	if len(prefix) == 1 && (candidate == "" || strings.HasSuffix(candidate, ":")) {
		candidate += "/"
	}
	return samePath(filepath.FromSlash(candidate), root)
}

func configuredOpenClawStateDir() string {
	if strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")) == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return openClawStateRoot(home)
}

func underConfiguredOpenClawStateRoot(path string) bool {
	root := configuredOpenClawStateDir()
	if root == "" {
		return false
	}
	inside, err := pathWithinRoot(root, path)
	return err == nil && inside
}

func underOpenClawRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+openclawRootMarker+"/") ||
		strings.HasPrefix(slashed, openclawRootMarker+"/") ||
		strings.Contains(slashed, "/"+openclawLegacyRootMarker+"/") ||
		strings.HasPrefix(slashed, openclawLegacyRootMarker+"/") ||
		underNamedOpenClawRoot(slashed) ||
		underConfiguredOpenClawStateRoot(path)
}

func underNamedOpenClawRoot(slashed string) bool {
	for _, segment := range strings.Split(slashed, "/") {
		if isOpenClawStateRootSegment(segment) && segment != openclawRootMarker && segment != openclawLegacyRootMarker {
			return true
		}
	}
	return false
}

// isPiArtifact matches JSONL files anywhere below Pi's versioned session tree.
// Directory names inside that tree encode the working directory and are not
// themselves stable identifiers, so the bounded root is the classifier.
func isPiArtifact(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".jsonl") && underPiRoot(path)
}

func underPiRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+piSessionsDir+"/") ||
		strings.HasPrefix(slashed, piSessionsDir+"/") ||
		underConfiguredRoot(path, "PI_CODING_AGENT_SESSION_DIR") ||
		underConfiguredSubtree(path, "PI_CODING_AGENT_DIR", "sessions")
}

// isKimiCodeArtifact admits only the documented terminal layout:
// sessions/<workDirKey>/<sessionId>/agents/<agentId>/wire.jsonl. This excludes
// session_index.jsonl, input history, and diagnostic logs from the parser.
func isKimiCodeArtifact(path string) bool {
	if !strings.EqualFold(filepath.Base(path), kimiWireFileName) || !underKimiSessions(path) {
		return false
	}
	parts := strings.Split(slashIdentity(path), "/")
	n := len(parts)
	return n >= 6 && parts[n-6] == "sessions" && parts[n-5] != "" &&
		parts[n-4] != "" && parts[n-3] == "agents" && parts[n-2] != ""
}

func underKimiSessions(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+kimiSessionsDir+"/") ||
		strings.HasPrefix(slashed, kimiSessionsDir+"/") ||
		underConfiguredSubtree(path, "KIMI_CODE_HOME", "sessions")
}

func underKimiCodeRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/"+kimiCodeHomeDir+"/") ||
		strings.HasPrefix(slashed, kimiCodeHomeDir+"/") ||
		underConfiguredRoot(path, "KIMI_CODE_HOME")
}

// isMuseCodeArtifact admits only the store's documented terminal layout:
// sessions/YYYY/MM/DD/<session-id>/session.jsonl, or the same tail with one or
// more subagent/<id>/ segments inserted before the file (subagents can spawn
// further subagents, so the nesting depth is unbounded). The "muse"+"sessions"
// segment pair is matched independently of XDG_DATA_HOME vs the home-relative
// default, since both roots end in exactly that pair.
func isMuseCodeArtifact(path string) bool {
	if !strings.EqualFold(filepath.Base(path), museSessionFileName) {
		return false
	}
	segments := strings.Split(slashIdentity(path), "/")
	for i, segment := range segments {
		if segment != "muse" || i+1 >= len(segments) || segments[i+1] != "sessions" {
			continue
		}
		if isMuseSessionTail(segments[i+2:]) {
			return true
		}
	}
	return false
}

// isMuseSessionTail validates YYYY/MM/DD/<session-id>/(subagent/<id>/)*session.jsonl.
func isMuseSessionTail(tail []string) bool {
	if len(tail) < 5 {
		return false
	}
	for _, d := range tail[:4] { // YYYY, MM, DD, session-id
		if d == "" {
			return false
		}
	}
	rest := tail[4:]
	for {
		if len(rest) == 1 {
			return strings.EqualFold(rest[0], museSessionFileName)
		}
		if len(rest) < 3 || rest[0] != subagentDirName || rest[1] == "" {
			return false
		}
		rest = rest[2:]
	}
}

func underMuseCodeRoot(path string) bool {
	slashed := slashIdentity(path)
	return strings.Contains(slashed, "/muse/sessions/") || strings.HasPrefix(slashed, "muse/sessions/")
}

// isSpecialFile rejects file types whose open/read may block or have side effects.
func isSpecialFile(mode fs.FileMode) bool {
	return mode&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice|fs.ModeIrregular) != 0
}

var errSymlinkEscapesRoot = errors.New("symlink target outside scan root")

// regularArtifactTarget admits regular files and in-root symlinks to regular
// files. Special files, broken links, directories, and escaping links are skipped.
func regularArtifactTarget(path string, typ fs.FileMode, walkRoot string) (string, bool, error) {
	if isSpecialFile(typ) {
		return "", false, nil
	}
	if typ&fs.ModeSymlink == 0 {
		info, err := os.Lstat(path)
		if err != nil {
			return "", false, err
		}
		return path, info.Mode().IsRegular(), nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false, err
	}
	inside, err := pathWithinRoot(walkRoot, target)
	if err != nil {
		return "", false, err
	}
	if !inside {
		return "", false, errSymlinkEscapesRoot
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", false, err
	}
	return target, info.Mode().IsRegular(), nil
}

func pathWithinRoot(root, path string) (bool, error) {
	rootAbs, err := absoluteResolvedPath(root)
	if err != nil {
		return false, err
	}
	pathAbs, err := absoluteResolvedPath(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(pathIdentity(rootAbs), pathIdentity(pathAbs))
	if err != nil {
		return false, err
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)), nil
}

func underConfiguredRoot(path, envName string) bool {
	root := os.Getenv(envName)
	if root == "" {
		return false
	}
	inside, err := pathWithinRoot(root, path)
	return err == nil && inside
}

func underConfiguredSubtree(path, envName string, subdirs ...string) bool {
	root := os.Getenv(envName)
	if root == "" {
		return false
	}
	for _, subdir := range subdirs {
		inside, err := pathWithinRoot(filepath.Join(root, subdir), path)
		if err == nil && inside {
			return true
		}
	}
	return false
}

func samePath(a, b string) bool {
	a, errA := absoluteResolvedPath(a)
	b, errB := absoluteResolvedPath(b)
	return errA == nil && errB == nil && pathIdentity(a) == pathIdentity(b)
}

func pathIdentity(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func slashIdentity(path string) string {
	return slashIdentityForOS(path, runtime.GOOS)
}

func slashIdentityForOS(path, goos string) string {
	if goos == "windows" {
		return strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	}
	return filepath.ToSlash(path)
}

func absoluteResolvedPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExists reports whether path is an existing regular file (following a
// symlink, like dirExists). Walk separately refuses special files.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
