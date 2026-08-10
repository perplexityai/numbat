package hook

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPiInstallLifecycleAndForeignCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extensions", "numbat.ts")
	rep, err := InstallWithOptions(AgentPi, path, "/opt/numbat", InstallOptions{RuntimeArgs: []string{"--output=file"}, Enforce: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentPi, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentPi, path))
	}
	body := readTestFile(t, path)
	for _, want := range []string{piPluginMarker, `pi.on("tool_call"`, `pi.on("message_end"`, `pi.on("tool_result"`, "tool_result: event.details", "spawnSync", `--enforce`, `sessionManager?.getSessionId`} {
		if !strings.Contains(body, want) {
			t.Errorf("Pi extension missing %q", want)
		}
	}
	if _, err := InstallWithOptions(AgentPi, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("idempotent reinstall: %v", err)
	}
	if _, err := Uninstall(AgentPi, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Pi extension remains after uninstall: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("export default () => {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentPi, path, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("foreign Pi extension should be refused")
	}
}

func TestKimiInstallPreservesConfigAndUsesOnlyDocumentedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "default_model = \"kimi-for-coding\"\n\n[[hooks]]\nevent = \"Notification\"\ncommand = \"notify\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentKimi, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	body := readTestFile(t, path)
	commandText := hookCommandText(body)
	if !strings.Contains(body, original) || strings.Count(body, kimiNumbatBlockStart) != 1 {
		t.Fatalf("Kimi config not preserved/idempotent:\n%s", body)
	}
	if strings.Contains(body, "name =") || strings.Contains(body, "type =") {
		t.Fatalf("Kimi block contains unsupported fields:\n%s", body)
	}
	if !strings.Contains(body, `event = "PreToolUse"`) || !strings.Contains(commandText, "--enforce") {
		t.Fatalf("Kimi enforcement hook missing:\n%s", body)
	}
	if _, err := InstallWithOptions(AgentKimi, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(readTestFile(t, path), kimiNumbatBlockStart) != 1 {
		t.Fatal("Kimi reinstall duplicated marker block")
	}
	partial := strings.Replace(readTestFile(t, path), "event = \"SessionStart\"\n", "", 1)
	if err := os.WriteFile(path, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := Status(AgentKimi, path); rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("Kimi partial status = %+v", rep)
	}
	if _, err := InstallWithOptions(AgentKimi, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(AgentKimi, path); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, path); got != original {
		t.Fatalf("Kimi uninstall changed user config:\n%s", got)
	}
}

func TestQwenInstallPreservesUnrelatedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"name":"numbat","type":"command","command":"foreign"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if Status(AgentQwen, path).Installed {
		t.Fatal("foreign Qwen hook named numbat must not be treated as owned")
	}
	if _, err := InstallWithOptions(AgentQwen, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["theme"]) != `"dark"` {
		t.Fatalf("theme not preserved: %s", doc["theme"])
	}
	gs, err := readGeminiSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hasNumbatQwenHooks(gs) || len(gs.hooks["PreToolUse"]) != 2 || len(gs.hooks["PermissionDenied"]) != 1 {
		t.Fatalf("Qwen hooks = %#v", gs.hooks)
	}
	if !strings.Contains(hookCommandText(gs.hooks["PreToolUse"][1].Hooks[0].Command), "--enforce") ||
		strings.Contains(hookCommandText(gs.hooks["PermissionDenied"][0].Hooks[0].Command), "--enforce") {
		t.Fatalf("Qwen enforce commands = pre:%#v denied:%#v", gs.hooks["PreToolUse"], gs.hooks["PermissionDenied"])
	}
	delete(gs.hooks, "SessionEnd")
	if err := writeGeminiSettings(path, gs, false); err != nil {
		t.Fatal(err)
	}
	if rep := Status(AgentQwen, path); rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("Qwen partial status = %+v", rep)
	}
	if _, err := InstallWithOptions(AgentQwen, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(AgentQwen, path); err != nil {
		t.Fatal(err)
	}
	gs, err = readGeminiSettings(path)
	if err != nil || hasNumbatQwenHooks(gs) || len(gs.hooks["PreToolUse"]) != 1 {
		t.Fatalf("Qwen uninstall = %#v, %v", gs.hooks["PreToolUse"], err)
	}
	if got := gs.hooks["PreToolUse"][0].Hooks[0]; got.Name != "numbat" || got.Command != "foreign" {
		t.Fatalf("Qwen uninstall changed foreign hook: %#v", got)
	}
}

func TestClineInstallWritesOwnedExecutableHooks(t *testing.T) {
	dir := t.TempDir()
	if _, err := InstallWithOptions(AgentCline, dir, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	for _, event := range clineHookEvents {
		path := clineHookPath(dir, event.name)
		body := readTestFile(t, path)
		if !strings.Contains(body, numbatHookMarker) {
			t.Errorf("%s missing marker", path)
		}
		if event.name == "PreToolUse" && !strings.Contains(body, "--enforce") {
			t.Errorf("PreToolUse missing enforcement flag")
		}
		if event.name != "PreToolUse" && strings.Contains(body, "--enforce") {
			t.Errorf("%s unexpectedly enforces", event.name)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0o100 == 0 {
				t.Errorf("%s is not executable: %v", path, err)
			}
		}
	}
	for _, goos := range []string{"linux", "windows"} {
		source := clineHookSourceForOS(goos, "/opt/numbat", clineHookEvent{name: "PreToolUse", lifecycle: "pre-tool"}, nil, true)
		if !strings.Contains(source, `{"cancel":false}`) {
			t.Errorf("%s Cline wrapper lacks fail-open fallback:\n%s", goos, source)
		}
	}
	if !Status(AgentCline, dir).Installed {
		t.Fatal("Cline status did not recognize full install")
	}
	if _, err := Uninstall(AgentCline, dir); err != nil {
		t.Fatal(err)
	}
	if Status(AgentCline, dir).Installed {
		t.Fatal("Cline remains installed")
	}
}

func TestClineHooksPathHonorsClineDir(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "cline-root")
	t.Setenv("CLINE_DIR", root)
	t.Setenv("CLINE_HOOKS_DIR", "")
	if got, want := ClineHooksPath(home), filepath.Join(root, "hooks"); got != want {
		t.Fatalf("ClineHooksPath = %q, want %q", got, want)
	}
}

func TestClineHooksPathPrefersRuntimeHooksDir(t *testing.T) {
	home := t.TempDir()
	clineRoot := filepath.Join(t.TempDir(), "cline-root")
	hooksRoot := filepath.Join(t.TempDir(), "runtime-hooks")
	t.Setenv("CLINE_DIR", clineRoot)
	t.Setenv("CLINE_HOOKS_DIR", "  "+hooksRoot+"  ")
	if got := ClineHooksPath(home); got != hooksRoot {
		t.Fatalf("ClineHooksPath = %q, want %q", got, hooksRoot)
	}
	if got := ClineRootPath(home); got != clineRoot {
		t.Fatalf("ClineRootPath = %q, want %q", got, clineRoot)
	}
}

func TestClineHooksPathIgnoresBlankClineDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLINE_DIR", "  ")
	t.Setenv("CLINE_HOOKS_DIR", "  ")
	if got, want := ClineHooksPath(home), filepath.Join(home, ".cline", "hooks"); got != want {
		t.Fatalf("ClineHooksPath = %q, want %q", got, want)
	}
}

func TestQwenSettingsPathMatchesDocumentedHomeExpansion(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		name string
		env  string
		want string
	}{
		{name: "blank", env: "  ", want: filepath.Join(home, ".qwen", "settings.json")},
		{name: "tilde", env: "~", want: filepath.Join(home, "settings.json")},
		{name: "tilde child", env: "~/.qwen-alt", want: filepath.Join(home, ".qwen-alt", "settings.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QWEN_HOME", tc.env)
			if got := QwenSettingsPath(home); got != tc.want {
				t.Fatalf("QwenSettingsPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClineUnixWrapperFailsOpenWhenNumbatCannotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX wrapper test")
	}
	dir := t.TempDir()
	failing := filepath.Join(dir, "failing-numbat")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(dir, "PreToolUse")
	source := clineHookSourceForOS("linux", failing, clineHookEvent{name: "PreToolUse", lifecycle: "pre-tool"}, nil, true)
	if err := os.WriteFile(hookPath, []byte(source), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(hookPath)
	cmd.Stdin = strings.NewReader(`{"preToolUse":{"tool":"execute_command","parameters":{"command":"pwd"}}}`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper returned a blocking process error: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != `{"cancel":false}` {
		t.Fatalf("wrapper fallback = %q, want Cline allow response", got)
	}
}

func TestClineUnixWrapperForwardsInputAndOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX wrapper test")
	}
	dir := t.TempDir()
	passthrough := filepath.Join(dir, "passthrough-numbat")
	if err := os.WriteFile(passthrough, []byte("#!/bin/sh\nIFS= read -r payload\nprintf '%s\\n' \"$payload\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(dir, "PreToolUse")
	source := clineHookSourceForOS("linux", passthrough, clineHookEvent{name: "PreToolUse", lifecycle: "pre-tool"}, nil, true)
	if err := os.WriteFile(hookPath, []byte(source), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := `{"cancel":true,"errorMessage":"blocked by fixture"}`
	cmd := exec.Command(hookPath)
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper returned an error: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != payload {
		t.Fatalf("wrapper output = %q, want forwarded payload", got)
	}
}

func TestAmpInstallAndAuggieWrappers(t *testing.T) {
	ampPath := filepath.Join(t.TempDir(), "amp", "plugins", "numbat.ts")
	if _, err := InstallWithOptions(AgentAmp, ampPath, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	amp := readTestFile(t, ampPath)
	for _, want := range []string{
		ampPluginMarker,
		`amp.on("tool.call"`,
		`tool_result: toolResultMetadata(event.output)`,
		`assistant_text: finalAssistantText(event.messages)`,
		"reject-and-continue",
		"spawnSync",
	} {
		if !strings.Contains(amp, want) {
			t.Errorf("Amp plugin missing %q", want)
		}
	}

	auggiePath := filepath.Join(t.TempDir(), ".augment", "settings.json")
	foreign := `/tmp/numbat--installed-by=numbat-foreign.sh`
	if runtime.GOOS == "windows" {
		foreign = `C:\Tools\numbat--installed-by=numbat-foreign.ps1`
	}
	seed := settingsFile{
		values: map[string]json.RawMessage{},
		hooks: map[string][]hookGroup{
			"SessionStart": {{Hooks: []hookRef{{Type: "command", Command: foreign}}}},
		},
	}
	if err := writeSettings(auggiePath, seed); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentAuggie, auggiePath, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	sf, err := readSettings(auggiePath)
	if err != nil {
		t.Fatal(err)
	}
	if !hasNumbatAuggieHooks(sf, auggiePath) {
		t.Fatal("Auggie settings missing numbat hooks")
	}
	if len(sf.hooks["SessionStart"]) != 2 || sf.hooks["SessionStart"][0].Hooks[0].Command != foreign {
		t.Fatalf("Auggie install removed foreign marker-like hook: %#v", sf.hooks["SessionStart"])
	}
	pre := auggieScriptPath(auggiePath, "pre-tool")
	if body := readTestFile(t, pre); !strings.Contains(body, numbatHookMarker) || !strings.Contains(body, "--enforce") {
		t.Fatalf("Auggie pre-tool wrapper is not owned/enforcing:\n%s", body)
	}
	if body := readTestFile(t, pre); runtime.GOOS == "windows" {
		if !strings.Contains(body, "$payload | &") {
			t.Fatalf("Auggie wrapper does not suppress success stdout:\n%s", body)
		}
	} else if !strings.Contains(body, ">/dev/null") {
		t.Fatalf("Auggie wrapper does not suppress success stdout:\n%s", body)
	}
	if _, err := Uninstall(AgentAuggie, auggiePath); err != nil {
		t.Fatal(err)
	}
	sf, err = readSettings(auggiePath)
	if err != nil || len(sf.hooks["SessionStart"]) != 1 || sf.hooks["SessionStart"][0].Hooks[0].Command != foreign {
		t.Fatalf("Auggie uninstall changed foreign marker-like hook: %#v, %v", sf.hooks["SessionStart"], err)
	}
	if _, err := os.Stat(pre); !os.IsNotExist(err) {
		t.Fatalf("Auggie wrapper remains: %v", err)
	}
}

func TestAuggiePartialStatusAndOrphanCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".augment", "settings.json")
	if _, err := InstallWithOptions(AgentAuggie, path, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	missing := auggieScriptPath(path, "pre-tool")
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	rep := Status(AgentAuggie, path)
	if rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("status after wrapper removal = %+v, want partial", rep)
	}

	// A lost settings file must not strand executable numbat-owned wrappers.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	rep, err := Uninstall(AgentAuggie, path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed {
		t.Fatalf("orphan cleanup report = %+v, want changed", rep)
	}
	for _, event := range auggieHookEvents {
		if _, err := os.Stat(auggieScriptPath(path, event.lifecycle)); !os.IsNotExist(err) {
			t.Fatalf("Auggie wrapper %s remains after orphan cleanup: %v", event.lifecycle, err)
		}
	}
}

func TestKiroInstallUsesOwnedGlobalHookFileSharedByIDEAndCLIv3(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("KIRO_HOME", "")
	path := filepath.Join(home, ".kiro", "hooks", "numbat.json")
	rep, err := InstallWithOptions(AgentKiro, path, "/opt/numbat", InstallOptions{Enforce: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Kiro IDE 1.0.182+", "default ~/.kiro", "Kiro CLI 2.13+", "v3 enabled"} {
		if !strings.Contains(rep.Message, want) {
			t.Errorf("Kiro install message %q missing %q", rep.Message, want)
		}
	}
	doc, err := readKiroHookFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != "v1" || len(doc.Hooks) != len(kiroHookEvents) {
		t.Fatalf("Kiro hook file = %#v", doc)
	}
	for _, entry := range doc.Hooks {
		command := hookCommandText(entry.Action.Command)
		if entry.Trigger == "PreToolUse" && !strings.Contains(command, "--enforce") {
			t.Errorf("Kiro PreToolUse command does not enforce: %q", entry.Action.Command)
		}
		if entry.Trigger != "PreToolUse" && strings.Contains(command, "--enforce") {
			t.Errorf("Kiro %s unexpectedly enforces", entry.Trigger)
		}
	}
	status := Status(AgentKiro, path)
	if !status.Installed {
		t.Fatal("Kiro status did not recognize owned file")
	}
	if !strings.Contains(status.Message, "Kiro IDE 1.0.182+") || !strings.Contains(status.Message, "Kiro CLI 2.13+") {
		t.Fatalf("Kiro status message does not describe shared IDE/CLI coverage: %q", status.Message)
	}
	if _, err := Uninstall(AgentKiro, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Kiro file remains after uninstall: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":"v1","hooks":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentKiro, path, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("foreign Kiro hook file should be refused")
	}
}

func TestKiroHooksPathHonorsKiroHome(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("KIRO_HOME", "")
	if got, want := KiroHooksPath("/home/u"), filepath.Join("/home/u", ".kiro", "hooks", "numbat.json"); got != want {
		t.Errorf("default KiroHooksPath = %q, want %q", got, want)
	}

	root := filepath.Join(t.TempDir(), "kiro profile")
	t.Setenv("KIRO_HOME", root)
	if got, want := KiroHooksPath("/unused"), filepath.Join(root, "hooks", "numbat.json"); got != want {
		t.Errorf("relocated KiroHooksPath = %q, want %q", got, want)
	}
	if note := kiroRuntimeCoverageNote(filepath.Join(root, "hooks", "numbat.json")); !strings.Contains(note, "Kiro CLI 2.13+") || !strings.Contains(note, "not documented for Kiro IDE") {
		t.Fatalf("relocated Kiro coverage note = %q", note)
	}
	if note := kiroRuntimeCoverageNote(filepath.Join(home, ".kiro", "hooks", "numbat.json")); !strings.Contains(note, "Kiro IDE 1.0.182+") || !strings.Contains(note, "separate root") || strings.Contains(note, "by Kiro CLI") {
		t.Fatalf("default IDE coverage note with KIRO_HOME set = %q", note)
	}

	t.Setenv("KIRO_HOME", filepath.Join(home, ".kiro"))
	if note := kiroRuntimeCoverageNote(filepath.Join(home, ".kiro", "hooks", "numbat.json")); !strings.Contains(note, "by Kiro CLI 2.13+") || strings.Contains(note, "separate root") {
		t.Fatalf("shared-root Kiro coverage note = %q", note)
	}
}

func TestGooseInstallUsesOwnedOpenPlugin(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".agents", "plugins", "numbat")
	rep, err := InstallWithOptions(AgentGoose, root, "/opt/numbat", InstallOptions{
		RuntimeArgs: []string{"--output=file", "--output-file=/tmp/findings.jsonl"},
		Enforce:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentGoose, root).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentGoose, root))
	}
	manifest, err := readGooseManifest(gooseManifestPath(root))
	if err != nil || manifest.Name != "numbat" || manifest.Description != goosePluginMarker {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	hooks, err := readGooseHooks(gooseHooksPath(root))
	if err != nil || len(hooks.Hooks) != len(gooseHookEvents) {
		t.Fatalf("hooks = %#v, %v", hooks, err)
	}
	for _, event := range gooseHookEvents {
		group := hooks.Hooks[event.event]
		if len(group) != 1 || len(group[0].Hooks) != 1 {
			t.Fatalf("Goose %s hook = %#v", event.event, group)
		}
		command := hookCommandText(group[0].Hooks[0].Command)
		if !strings.Contains(command, numbatHookMarker) || !strings.Contains(command, "--output-file=/tmp/findings.jsonl") {
			t.Errorf("Goose %s command missing runtime args: %q", event.event, command)
		}
		if got, want := strings.Contains(command, "--enforce"), event.event == "PreToolUse"; got != want {
			t.Errorf("Goose %s enforce=%t, want %t: %q", event.event, got, want, command)
		}
		if group[0].Hooks[0].Timeout != event.timeout {
			t.Errorf("Goose %s timeout=%d, want %d", event.event, group[0].Hooks[0].Timeout, event.timeout)
		}
	}

	// An incomplete owned install is reported explicitly and cleaned up.
	if err := os.Remove(gooseManifestPath(root)); err != nil {
		t.Fatal(err)
	}
	if partial := Status(AgentGoose, root); partial.Installed || !strings.Contains(partial.Message, "partial") {
		t.Fatalf("partial status = %+v", partial)
	}
	if rep, err = Uninstall(AgentGoose, root); err != nil || !rep.Changed {
		t.Fatalf("partial uninstall = %+v, %v", rep, err)
	}
	if _, err := os.Stat(gooseHooksPath(root)); !os.IsNotExist(err) {
		t.Fatalf("owned Goose hooks remain: %v", err)
	}

	foreign := filepath.Join(t.TempDir(), ".agents", "plugins", "numbat")
	if err := os.MkdirAll(filepath.Dir(gooseManifestPath(foreign)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gooseManifestPath(foreign), []byte(`{"name":"foreign","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentGoose, foreign, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("foreign Goose manifest should be refused")
	}

	occupied := filepath.Join(t.TempDir(), ".agents", "plugins", "numbat")
	if err := os.MkdirAll(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "foreign.txt"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentGoose, occupied, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("non-empty foreign Goose plugin directory should be refused")
	}
	if got := readTestFile(t, filepath.Join(occupied, "foreign.txt")); got != "keep\n" {
		t.Fatalf("foreign Goose plugin content changed: %q", got)
	}
}

func TestKiloInstallUsesOwnedGlobalPlugin(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config", "kilo", "plugin", "numbat.ts")
	rep, err := InstallWithOptions(AgentKilo, path, "/opt/numbat", InstallOptions{
		RuntimeArgs: []string{"--output=file"},
		Enforce:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentKilo, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentKilo, path))
	}
	body := readTestFile(t, path)
	for _, want := range []string{
		kiloPluginMarker,
		`import type { Plugin } from "@kilocode/plugin"`,
		`"tool.execute.before"`,
		`spawnSync`,
		`throw new Error(reason)`,
		`export default { id: "numbat", server }`,
		`"--enforce"`,
		`"--output=file"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Kilo plugin missing %q", want)
		}
	}
	if strings.Count(body, `"--enforce"`) != 1 {
		t.Fatalf("Kilo plugin should carry one global enforce arg: %s", body)
	}
	if _, err := Uninstall(AgentKilo, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Kilo plugin remains after uninstall: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("export default { id: 'foreign', server: async () => ({}) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentKilo, path, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("foreign Kilo plugin should be refused")
	}
}

func TestOpenHandsInstallPreservesRepositoryHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo", ".openhands", "hooks.json")
	seed := `{
  "pre_tool_use": [{"matcher":"terminal","hooks":[{"command":"./foreign.sh","timeout":5}]}],
  "custom": {"keep": true}
}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := InstallWithOptions(AgentOpenHands, path, "/opt/numbat", InstallOptions{
		RuntimeArgs: []string{"--output=file"},
		Enforce:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !Status(AgentOpenHands, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentOpenHands, path))
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(sf.values["pre_tool_use"]) == "" || string(sf.values["custom"]) == "" {
		t.Fatalf("native flat OpenHands config was not preserved: %#v", sf.values)
	}
	if complete, any := openHandsHookState(sf); !complete || !any {
		t.Fatalf("OpenHands hook state = complete:%t any:%t", complete, any)
	}
	for _, event := range openHandsHookEvents {
		groups := sf.hooks[event.settingsKey]
		if len(groups) != 1 || groups[0].Matcher != "*" || len(groups[0].Hooks) != 1 {
			t.Fatalf("OpenHands %s = %#v", event.settingsKey, groups)
		}
		ref := groups[0].Hooks[0]
		if !isNumbatHookCommand(ref.Command) || ref.Args != nil || ref.Timeout != event.timeout {
			t.Errorf("OpenHands %s hook = %#v", event.settingsKey, ref)
		}
		if got, want := strings.Contains(hookCommandText(ref.Command), "--enforce"), event.settingsKey == "PreToolUse"; got != want {
			t.Errorf("OpenHands %s enforce=%t, want %t: %q", event.settingsKey, got, want, ref.Command)
		}
	}
	if _, err := InstallWithOptions(AgentOpenHands, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range openHandsHookEvents {
		if len(sf.hooks[event.settingsKey]) != 1 {
			t.Fatalf("OpenHands reinstall duplicated %s: %#v", event.settingsKey, sf.hooks[event.settingsKey])
		}
	}
	if _, err := Uninstall(AgentOpenHands, path); err != nil {
		t.Fatal(err)
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if complete, any := openHandsHookState(sf); complete || any {
		t.Fatalf("OpenHands hooks remain after uninstall: complete:%t any:%t", complete, any)
	}
	if string(sf.values["pre_tool_use"]) == "" || string(sf.values["custom"]) == "" {
		t.Fatalf("OpenHands uninstall removed native config: %#v", sf.values)
	}
}

func TestOpenHandsRequiresRepositoryHooksPath(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "hooks.json"), filepath.Join(t.TempDir(), ".openhands", "other.json")} {
		if _, err := InstallWithOptions(AgentOpenHands, path, "/opt/numbat", InstallOptions{}); err == nil {
			t.Errorf("InstallWithOptions accepted non-OpenHands path %q", path)
		}
	}
}

func TestGooseAndKiloDefaultPaths(t *testing.T) {
	home := t.TempDir()
	if got, want := GoosePluginPath(home), filepath.Join(home, ".agents", "plugins", "numbat"); got != want {
		t.Fatalf("GoosePluginPath = %q, want %q", got, want)
	}
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got, want := KiloPluginPath(home), filepath.Join(xdg, "kilo", "plugin", "numbat.ts"); got != want {
		t.Fatalf("KiloPluginPath = %q, want %q", got, want)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
