package hook

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	openClawManifestFile = "openclaw.plugin.json"
	openClawPackageFile  = "package.json"
	openClawSourceFile   = "index.js"
	openClawPluginMarker = "numbat-managed OpenClaw hook plugin"
	openClawSourceMarker = "// numbat-managed OpenClaw plugin - do not edit"
	openClawChecksumMark = openClawSourceMarker + "; sha256="
	openClawRootDir      = ".openclaw"
)

type openClawPluginManifest struct {
	ID           string                     `json:"id"`
	Name         string                     `json:"name"`
	Description  string                     `json:"description"`
	Version      string                     `json:"version"`
	Activation   openClawPluginActivation   `json:"activation"`
	ConfigSchema openClawPluginConfigSchema `json:"configSchema"`
}

type openClawPluginActivation struct {
	OnStartup      bool     `json:"onStartup"`
	OnCapabilities []string `json:"onCapabilities"`
}

type openClawPluginConfigSchema struct {
	Type                 string         `json:"type"`
	AdditionalProperties bool           `json:"additionalProperties"`
	Properties           map[string]any `json:"properties"`
}

type openClawPackage struct {
	Name             string                    `json:"name"`
	Version          string                    `json:"version"`
	Description      string                    `json:"description"`
	Private          bool                      `json:"private"`
	Type             string                    `json:"type"`
	PeerDependencies map[string]string         `json:"peerDependencies"`
	OpenClaw         openClawPackageDescriptor `json:"openclaw"`
}

type openClawPackageDescriptor struct {
	Extensions []string                  `json:"extensions"`
	Compat     openClawPackageCompatible `json:"compat"`
	Build      openClawPackageBuild      `json:"build"`
}

type openClawPackageCompatible struct {
	PluginAPI string `json:"pluginApi"`
}

type openClawPackageBuild struct {
	OpenClawVersion string `json:"openclawVersion"`
}

// OpenClawPluginPath returns the native global plugin directory discovered by
// the Gateway. Its config-root precedence is OPENCLAW_STATE_DIR, then the
// directory containing OPENCLAW_CONFIG_PATH, then the effective home .openclaw
// directory. OpenClaw's --profile flag projects the first two variables inside
// its process; OPENCLAW_PROFILE alone does not select a root. This intentionally
// differs from at-rest state resolution, which retains a legacy .clawdbot
// fallback.
func OpenClawPluginPath(home string) string {
	return filepath.Join(openClawConfigRoot(home), "extensions", "numbat")
}

func openClawConfigRoot(home string) string {
	effectiveHome := openClawEffectiveHome(home)
	if state := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")); state != "" {
		return resolveOpenClawPath(state, effectiveHome)
	}
	if config := strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH")); config != "" {
		return filepath.Dir(resolveOpenClawPath(config, effectiveHome))
	}
	return filepath.Join(effectiveHome, openClawRootDir)
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

func openClawManifestPath(root string) string { return filepath.Join(root, openClawManifestFile) }

func openClawPackagePath(root string) string { return filepath.Join(root, openClawPackageFile) }

func openClawSourcePath(root string) string { return filepath.Join(root, openClawSourceFile) }

func openClawDocuments(binary string, runtimeArgs []string, enforce bool) (openClawPluginManifest, openClawPackage, string) {
	manifest := openClawPluginManifest{
		ID:          "numbat",
		Name:        "Numbat",
		Description: openClawPluginMarker,
		Version:     "0.1.0",
		Activation: openClawPluginActivation{
			OnStartup:      true,
			OnCapabilities: []string{"hook"},
		},
		ConfigSchema: openClawPluginConfigSchema{
			Type:                 "object",
			AdditionalProperties: false,
			Properties:           map[string]any{},
		},
	}
	pkg := openClawPackage{
		Name:        "@perplexityai/numbat-openclaw",
		Version:     "0.1.0",
		Description: openClawPluginMarker,
		Private:     true,
		Type:        "module",
		PeerDependencies: map[string]string{
			"openclaw": ">=2026.7.1",
		},
		OpenClaw: openClawPackageDescriptor{
			Extensions: []string{"./index.js"},
			Compat: openClawPackageCompatible{
				PluginAPI: ">=2026.7.1",
			},
			Build: openClawPackageBuild{
				OpenClawVersion: "2026.7.1",
			},
		},
	}
	return manifest, pkg, openClawPluginSource(binary, runtimeArgs, enforce)
}

func openClawPluginSource(binary string, runtimeArgs []string, enforce bool) string {
	extra := []string{numbatHookMarker}
	extra = append(extra, runtimeArgs...)
	if enforce {
		extra = append(extra, "--enforce")
	}
	var b strings.Builder
	b.WriteString("// Generated by `numbat hook install --agent openclaw`; subprocess faults and the internal deadline return no block.\n")
	b.WriteString("import { spawn } from \"node:child_process\";\n\n")
	b.WriteString("const NUMBAT_BIN = " + jsString(binary) + ";\n")
	b.WriteString("const EXTRA_ARGS = " + jsArgs(extra) + ";\n")
	b.WriteString("const ENFORCE = " + fmt.Sprintf("%t", enforce) + ";\n")
	b.WriteString("const MAX_STDIN_BYTES = 4 * 1024 * 1024;\n")
	b.WriteString("const MAX_STDOUT_BYTES = 1024 * 1024;\n")
	b.WriteString("const NUMBAT_DEADLINE_MS = 9000;\n")
	b.WriteString("const OBSERVATION_DEADLINE_MS = 30000;\n\n")
	b.WriteString(`function eventValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

function objectValue(value) {
  return eventValue(value) ?? {};
}

function observedAt(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value) return value;
  return new Date().toISOString();
}

function sessionIdentity(event = {}, ctx = {}) {
  event = objectValue(event);
  ctx = objectValue(ctx);
  return event.sessionKey ?? ctx.sessionKey ?? event.sessionId ?? ctx.sessionId;
}

function envelope(event = {}, ctx = {}) {
  event = objectValue(event);
  ctx = objectValue(ctx);
  return {
    timestamp: observedAt(event.timestamp),
    session_id: sessionIdentity(event, ctx),
    run_id: event.runId ?? ctx.runId,
    agent_id: ctx.agentId,
  };
}

function toolPayload(event = {}, ctx = {}) {
  event = objectValue(event);
  ctx = objectValue(ctx);
  return {
    ...envelope(event, ctx),
    tool_name: event.toolName ?? ctx.toolName,
    tool_input: event.params ?? {},
    tool_call_id: event.toolCallId ?? ctx.toolCallId,
    tool_kind: event.toolKind ?? ctx.toolKind,
    tool_input_kind: event.toolInputKind ?? ctx.toolInputKind,
    derived_paths: Array.isArray(event.derivedPaths) ? event.derivedPaths : undefined,
    cwd: typeof event.params?.cwd === "string" ? event.params.cwd
      : typeof event.params?.workdir === "string" ? event.params.workdir : undefined,
  };
}

function conversationPayload(event = {}, ctx = {}) {
  event = objectValue(event);
  ctx = objectValue(ctx);
  return {
    ...envelope(event, ctx),
    session_id: ctx.sessionKey ?? event.sessionId ?? ctx.sessionId,
    cwd: ctx.workspaceDir,
    model: event.model ?? ctx.modelId,
    model_provider: event.provider ?? ctx.modelProviderId,
  };
}

function assistantText(value) {
  if (!Array.isArray(value)) return undefined;
  const parts = value.filter((part) => typeof part === "string" && part.trim().length > 0);
  return parts.length > 0 ? parts.join("\n") : undefined;
}

function toolExitCode(result) {
  result = objectValue(result);
  const details = objectValue(result.details);
  return Number.isSafeInteger(details.exitCode) ? details.exitCode : undefined;
}

function serialize(payload) {
  try {
    const input = JSON.stringify(payload);
    if (typeof input !== "string" || Buffer.byteLength(input, "utf8") > MAX_STDIN_BYTES) {
      process.stderr.write("numbat: hook payload exceeds input limit; capture omitted\n");
      return undefined;
    }
    return input;
  } catch (_) {
    return undefined;
  }
}

function forward(lifecycle, payload) {
  const input = serialize(payload);
  if (input === undefined) return;
  let child;
  try {
    child = spawn(NUMBAT_BIN, ["hook", lifecycle, "--agent", "openclaw", ...EXTRA_ARGS], {
      stdio: ["pipe", "ignore", "inherit"],
      detached: true,
      windowsHide: true,
    });
    const timer = setTimeout(() => { try { child.kill(); } catch (_) {} }, OBSERVATION_DEADLINE_MS);
    timer.unref?.();
    child.on("error", () => clearTimeout(timer));
    child.on("close", () => clearTimeout(timer));
    child.stdin.on("error", () => { try { child.kill(); } catch (_) {} });
    child.stdin.end(input);
    child.unref();
  } catch (_) {
    try { child?.kill(); } catch (_) {}
  }
}

function enforceTool(event, ctx) {
  event = eventValue(event);
  if (event === undefined) return Promise.resolve(undefined);
  ctx = objectValue(ctx);
  const payload = toolPayload(event, ctx);
  if (!ENFORCE) {
    forward("pre-tool", payload);
    return Promise.resolve(undefined);
  }
  const input = serialize(payload);
  if (input === undefined) return Promise.resolve(undefined);
  return new Promise((resolve) => {
    let child;
    let settled = false;
    let stdoutBytes = 0;
    const stdoutChunks = [];
    const finish = (decision) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(decision);
    };
    const timer = setTimeout(() => {
      try { child?.kill(); } catch (_) {}
      finish(undefined);
    }, NUMBAT_DEADLINE_MS);
    try {
      child = spawn(NUMBAT_BIN, ["hook", "pre-tool", "--agent", "openclaw", ...EXTRA_ARGS], {
        stdio: ["pipe", "pipe", "inherit"],
        windowsHide: true,
      });
      child.on("error", () => finish(undefined));
      child.stdout.on("data", (chunk) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        stdoutBytes += bytes.length;
        if (stdoutBytes > MAX_STDOUT_BYTES) {
          try { child.kill(); } catch (_) {}
          finish(undefined);
          return;
        }
        stdoutChunks.push(bytes);
      });
      child.on("close", (code) => {
        if (settled || code !== 0 || stdoutBytes === 0) return finish(undefined);
        try {
          const stdout = Buffer.concat(stdoutChunks, stdoutBytes).toString("utf8");
          const response = JSON.parse(stdout);
          if (response?.block === true) {
            const reason = typeof response.blockReason === "string" && response.blockReason
              ? response.blockReason
              : "Blocked by Numbat policy";
            return finish({ block: true, blockReason: reason });
          }
        } catch (_) {}
        finish(undefined);
      });
      child.stdin.on("error", () => {
        try { child.kill(); } catch (_) {}
        finish(undefined);
      });
      child.stdin.end(input);
    } catch (_) {
      try { child?.kill(); } catch (_) {}
      finish(undefined);
    }
  });
}

export default {
  id: "numbat",
  name: "Numbat",
  description: "numbat-managed OpenClaw hook plugin",
  register(api) {
    api.on("session_start", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("session-start", { ...envelope(event, ctx), resumed_from: event.resumedFrom });
    });
    api.on("message_received", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("prompt-submit", {
        ...envelope(event, ctx), prompt: event.content, channel: ctx.channelId,
        message_id: event.messageId, boundary: "transport",
      });
    });
    api.on("llm_input", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("prompt-submit", {
        ...conversationPayload(event, ctx), boundary: "model",
        prompt: typeof event.prompt === "string" ? event.prompt : undefined,
      });
    });
    api.on("before_tool_call", enforceTool, { priority: 50, timeoutMs: 10000 });
    api.on("after_tool_call", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("post-tool", {
        ...toolPayload(event, ctx),
        duration_ms: event.durationMs,
        is_error: typeof event.error === "string" && event.error.length > 0,
        exit_code: toolExitCode(event.result),
        tool_response: { result: event.result, error: event.error },
      });
    });
    api.on("llm_output", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      const text = assistantText(event.assistantTexts);
      if (text === undefined) return;
      forward("assistant", {
        ...conversationPayload(event, ctx), boundary: "model", assistant_text: text,
      });
    });
    api.on("message_sent", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("assistant", {
        ...envelope(event, ctx), channel: ctx.channelId,
        message_id: event.messageId, success: event.success, boundary: "transport",
      });
    });
    api.on("session_end", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("session-end", {
        ...envelope(event, ctx), duration_ms: event.durationMs,
        message_count: event.messageCount, reason: event.reason,
      });
    });
    api.on("subagent_spawned", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("session-start", {
        timestamp: new Date().toISOString(), session_id: event.childSessionKey,
        parent_session_id: ctx.requesterSessionKey, run_id: event.runId ?? ctx.runId,
        sub_agent: event.label ?? event.agentId, agent_id: event.agentId,
        model: event.resolvedModel, model_provider: event.resolvedProvider,
      });
    });
    api.on("subagent_ended", (rawEvent, rawCtx) => {
      const event = eventValue(rawEvent);
      if (event === undefined) return;
      const ctx = objectValue(rawCtx);
      forward("session-end", {
        timestamp: observedAt(event.endedAt), session_id: event.targetSessionKey,
        run_id: event.runId ?? ctx.runId, sub_agent: event.targetKind,
        reason: event.reason, outcome: event.outcome,
        is_error: typeof event.error === "string" && event.error.length > 0,
      });
    });
  },
};
`)
	return sealOpenClawSource(b.String())
}

func sealOpenClawSource(body string) string {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%s%x\n%s", openClawChecksumMark, sum, body)
}

func validOpenClawSource(data []byte) bool {
	source := string(data)
	lineEnd := strings.IndexByte(source, '\n')
	if lineEnd < 0 || !strings.HasPrefix(source[:lineEnd], openClawChecksumMark) {
		return false
	}
	want := strings.TrimPrefix(source[:lineEnd], openClawChecksumMark)
	body := source[lineEnd+1:]
	sum := sha256.Sum256([]byte(body))
	return len(want) == sha256.Size*2 && strings.EqualFold(want, fmt.Sprintf("%x", sum))
}

func readOpenClawManifest(path string) (openClawPluginManifest, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		return openClawPluginManifest{}, err
	}
	var doc openClawPluginManifest
	if err := json.Unmarshal(data, &doc); err != nil {
		return openClawPluginManifest{}, fmt.Errorf("parse OpenClaw plugin manifest %s: %w", path, err)
	}
	return doc, nil
}

func readOpenClawPackage(path string) (openClawPackage, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		return openClawPackage{}, err
	}
	var doc openClawPackage
	if err := json.Unmarshal(data, &doc); err != nil {
		return openClawPackage{}, fmt.Errorf("parse OpenClaw package metadata %s: %w", path, err)
	}
	return doc, nil
}

func isNumbatOpenClawManifestDocument(doc openClawPluginManifest) bool {
	return doc.ID == "numbat" && doc.Description == openClawPluginMarker
}

func isValidNumbatOpenClawManifest(doc openClawPluginManifest) bool {
	return isNumbatOpenClawManifestDocument(doc) && doc.Name == "Numbat" && doc.Version == "0.1.0" &&
		doc.Activation.OnStartup && len(doc.Activation.OnCapabilities) == 1 && doc.Activation.OnCapabilities[0] == "hook" &&
		doc.ConfigSchema.Type == "object" && !doc.ConfigSchema.AdditionalProperties && len(doc.ConfigSchema.Properties) == 0
}

func isNumbatOpenClawPackageDocument(doc openClawPackage) bool {
	return doc.Name == "@perplexityai/numbat-openclaw" && doc.Description == openClawPluginMarker
}

func isValidNumbatOpenClawPackage(doc openClawPackage) bool {
	return isNumbatOpenClawPackageDocument(doc) && doc.Version == "0.1.0" && doc.Private && doc.Type == "module" &&
		doc.PeerDependencies["openclaw"] == ">=2026.7.1" && len(doc.OpenClaw.Extensions) == 1 &&
		doc.OpenClaw.Extensions[0] == "./index.js" && doc.OpenClaw.Compat.PluginAPI == ">=2026.7.1" &&
		doc.OpenClaw.Build.OpenClawVersion == "2026.7.1"
}

func openClawFileOwnership(root string) (manifest, pkg, source bool, err error) {
	manifestDoc, manifestErr := readOpenClawManifest(openClawManifestPath(root))
	if manifestErr == nil {
		manifest = isNumbatOpenClawManifestDocument(manifestDoc)
	} else if !os.IsNotExist(manifestErr) {
		return false, false, false, manifestErr
	}
	packageDoc, packageErr := readOpenClawPackage(openClawPackagePath(root))
	if packageErr == nil {
		pkg = isNumbatOpenClawPackageDocument(packageDoc)
	} else if !os.IsNotExist(packageErr) {
		return false, false, false, packageErr
	}
	_, source, sourceErr := textHookFileOwnership(openClawSourcePath(root), openClawSourceMarker)
	if sourceErr != nil {
		return false, false, false, sourceErr
	}
	return manifest, pkg, source, nil
}

func openClawFileValidity(root string) (manifest, pkg, source bool, err error) {
	manifestDoc, manifestErr := readOpenClawManifest(openClawManifestPath(root))
	if manifestErr == nil {
		manifest = isValidNumbatOpenClawManifest(manifestDoc)
	} else if !os.IsNotExist(manifestErr) {
		return false, false, false, manifestErr
	}
	packageDoc, packageErr := readOpenClawPackage(openClawPackagePath(root))
	if packageErr == nil {
		pkg = isValidNumbatOpenClawPackage(packageDoc)
	} else if !os.IsNotExist(packageErr) {
		return false, false, false, packageErr
	}
	sourceData, sourceErr := readHookConfigFile(openClawSourcePath(root))
	if sourceErr == nil {
		source = validOpenClawSource(sourceData)
	} else if !os.IsNotExist(sourceErr) {
		return false, false, false, sourceErr
	}
	return manifest, pkg, source, nil
}

func installOpenClawWithArgs(root, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentOpenClaw, SettingsPath: root, Supported: true}
	if entries, err := os.ReadDir(root); err == nil {
		allMissing := true
		for _, path := range []string{openClawManifestPath(root), openClawPackagePath(root), openClawSourcePath(root)} {
			if _, statErr := os.Lstat(path); statErr == nil || !os.IsNotExist(statErr) {
				allMissing = false
			}
		}
		if allMissing && len(entries) > 0 {
			return rep, fmt.Errorf("refusing to claim non-empty OpenClaw plugin directory without numbat-owned files at %s", root)
		}
	} else if !os.IsNotExist(err) {
		return rep, err
	}

	for _, check := range []struct {
		path string
		kind string
		read func(string) (bool, error)
	}{
		{openClawManifestPath(root), "manifest", func(path string) (bool, error) {
			doc, err := readOpenClawManifest(path)
			return isNumbatOpenClawManifestDocument(doc), err
		}},
		{openClawPackagePath(root), "package metadata", func(path string) (bool, error) {
			doc, err := readOpenClawPackage(path)
			return isNumbatOpenClawPackageDocument(doc), err
		}},
		{openClawSourcePath(root), "entry point", func(path string) (bool, error) {
			exists, owned, err := textHookFileOwnership(path, openClawSourceMarker)
			return !exists || owned, err
		}},
	} {
		owned, err := check.read(check.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return rep, err
		}
		if !owned {
			return rep, fmt.Errorf("refusing to overwrite existing non-numbat OpenClaw plugin %s at %s", check.kind, check.path)
		}
	}

	manifest, pkg, source := openClawDocuments(binary, runtimeArgs, enforce)
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return rep, err
	}
	packageData, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return rep, err
	}
	if err := writeFileAtomic(openClawManifestPath(root), append(manifestData, '\n')); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(openClawPackagePath(root), append(packageData, '\n')); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(openClawSourcePath(root), []byte(source)); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed numbat OpenClaw plugin (pin or enable trust as needed, then restart and verify the Gateway)"
	if enforce {
		rep.Message = "installed numbat OpenClaw plugin in enforce mode (pin or enable trust as needed, then restart and verify the Gateway)"
	}
	return rep, nil
}

func uninstallOpenClaw(root string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentOpenClaw, SettingsPath: root, Supported: true}
	manifest, pkg, source, err := openClawFileOwnership(root)
	if err != nil {
		return rep, err
	}
	for path, owned := range map[string]bool{
		openClawManifestPath(root): manifest,
		openClawPackagePath(root):  pkg,
		openClawSourcePath(root):   source,
	} {
		if !owned {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return rep, err
		}
		rep.Changed = true
	}
	if rep.Changed {
		_ = os.Remove(root)
		rep.Message = "removed numbat OpenClaw plugin files"
	} else {
		rep.Message = "no numbat OpenClaw plugin present"
	}
	return rep, nil
}

func statusOpenClaw(root string) InstallReport {
	rep := InstallReport{Agent: AgentOpenClaw, SettingsPath: root, Supported: true}
	ownedManifest, ownedPackage, ownedSource, err := openClawFileOwnership(root)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	manifest, pkg, source, err := openClawFileValidity(root)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = manifest && pkg && source
	if rep.Installed {
		rep.Message = "numbat OpenClaw plugin package present and valid (runtime activation not verified)"
	} else if ownedManifest || ownedPackage || ownedSource {
		rep.Message = "partial or invalid numbat OpenClaw plugin package install"
	} else {
		rep.Message = "numbat OpenClaw plugin package not installed"
	}
	return rep
}

func configReadableOpenClaw(root string) error {
	info, err := os.Stat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: OpenClaw plugin path is not a directory", root)
	}
	for _, path := range []string{openClawManifestPath(root), openClawPackagePath(root), openClawSourcePath(root)} {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		switch filepath.Base(path) {
		case openClawManifestFile:
			_, err = readOpenClawManifest(path)
		case openClawPackageFile:
			_, err = readOpenClawPackage(path)
		default:
			_, err = readHookConfigFile(path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
