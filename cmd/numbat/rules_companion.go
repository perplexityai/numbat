package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
	"go.yaml.in/yaml/v3"
)

const maxRuleTestFileSize = 4 * 1024 * 1024

type ruleTestFile struct {
	RuleID string         `yaml:"rule_id"`
	Cases  []ruleTestCase `yaml:"cases"`
}

type ruleTestCase struct {
	Name              string          `yaml:"name"`
	Expect            string          `yaml:"expect"`
	ExpectEnforcement *bool           `yaml:"expect_enforcement,omitempty"`
	Events            []ruleTestEvent `yaml:"events"`
}

type ruleTestEvent struct {
	model.Event
}

func (e *ruleTestEvent) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("event fixture must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if _, ok := ruleTestEventFields[key]; !ok {
			return fmt.Errorf("unknown event field %q", key)
		}
		if key == "evidence" {
			if err := validateRuleTestEvidenceFields(node.Content[i+1]); err != nil {
				return err
			}
		}
	}
	var raw map[string]any
	if err := node.Decode(&raw); err != nil {
		return err
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &e.Event)
}

var (
	ruleTestEventFields    = jsonFieldSet(model.Event{})
	ruleTestEvidenceFields = jsonFieldSet(model.Evidence{})
)

func jsonFieldSet(v any) map[string]struct{} {
	out := map[string]struct{}{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func validateRuleTestEvidenceFields(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("evidence fixture must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if _, ok := ruleTestEvidenceFields[key]; !ok {
			return fmt.Errorf("unknown evidence field %q", key)
		}
	}
	return nil
}

func runCompanionRuleTests(rulesDirs []string, eng *rule.Engine) (int, error) {
	if len(rulesDirs) == 0 {
		return 0, nil
	}
	known := map[string]struct{}{}
	for _, id := range eng.RuleIDs() {
		known[id] = struct{}{}
	}
	paths, err := findCompanionRuleTests(rulesDirs)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, path := range paths {
		count, err := runCompanionRuleTestFile(path, eng, known)
		if err != nil {
			return total, err
		}
		total += count
	}
	return total, nil
}

func findCompanionRuleTests(rulesDirs []string) ([]string, error) {
	var paths []string
	for _, dir := range rulesDirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !rule.IsRuleTestFile(path) {
				return nil
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk rule tests %q: %w", dir, err)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func runCompanionRuleTestFile(path string, eng *rule.Engine, knownRules map[string]struct{}) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open rule tests %q: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxRuleTestFileSize+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return 0, fmt.Errorf("read rule tests %q: %w", path, errors.Join(readErr, closeErr))
	}
	if len(data) > maxRuleTestFileSize {
		return 0, fmt.Errorf("read rule tests %q: exceeds %d bytes", path, maxRuleTestFileSize)
	}
	var tf ruleTestFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&tf); err != nil {
		return 0, fmt.Errorf("decode rule tests %q: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return 0, fmt.Errorf("decode rule tests %q: multiple YAML documents are not supported", path)
		}
		return 0, fmt.Errorf("decode rule tests %q: %w", path, err)
	}
	tf.RuleID = strings.TrimSpace(tf.RuleID)
	if tf.RuleID == "" {
		return 0, fmt.Errorf("rule tests %q: missing rule_id", path)
	}
	companionID, err := companionRuleID(path)
	if err != nil {
		return 0, err
	}
	if tf.RuleID != companionID {
		return 0, fmt.Errorf("rule tests %q: rule_id %q does not match companion rule %q", path, tf.RuleID, companionID)
	}
	if _, ok := knownRules[tf.RuleID]; !ok {
		return 0, fmt.Errorf("rule tests %q: unknown rule_id %q", path, tf.RuleID)
	}
	for _, r := range eng.DecisionRules() {
		if r.ID == tf.RuleID {
			return 0, fmt.Errorf("rule tests %q: decision-model matches cannot be tested by offline companion fixtures", path)
		}
	}
	if len(tf.Cases) == 0 {
		return 0, fmt.Errorf("rule tests %q: no cases", path)
	}
	for i, c := range tf.Cases {
		if err := runCompanionRuleTestCase(eng, tf.RuleID, path, i, c); err != nil {
			return 0, err
		}
	}
	return len(tf.Cases), nil
}

func companionRuleID(testPath string) (string, error) {
	ext := filepath.Ext(testPath)
	base := strings.TrimSuffix(testPath, ext)
	rulePath := strings.TrimSuffix(base, "_tests") + ext
	f, err := os.Open(rulePath)
	if err != nil {
		return "", fmt.Errorf("rule tests %q: open companion rule %q: %w", testPath, rulePath, err)
	}
	source, loadErr := rule.LoadSource(f, rulePath)
	closeErr := f.Close()
	if loadErr != nil || closeErr != nil {
		return "", errors.Join(loadErr, closeErr)
	}
	return source.Rules[0].ID, nil
}

func runCompanionRuleTestCase(eng *rule.Engine, ruleID, path string, index int, c ruleTestCase) error {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = fmt.Sprintf("#%d", index+1)
	}
	if len(c.Events) == 0 {
		return fmt.Errorf("rule tests %q case %s: no events", path, name)
	}
	result, err := companionCaseMatches(eng, ruleID, c.Events)
	if err != nil {
		return fmt.Errorf("rule tests %q case %s: %w", path, name, err)
	}
	switch strings.TrimSpace(c.Expect) {
	case "match":
		if !result.matched {
			return fmt.Errorf("rule tests %q case %s: expected match for %s", path, name, ruleID)
		}
		if c.ExpectEnforcement != nil && result.enforcement != *c.ExpectEnforcement {
			return fmt.Errorf(
				"rule tests %q case %s: enforcement match = %t, want %t for %s",
				path, name, result.enforcement, *c.ExpectEnforcement, ruleID,
			)
		}
	case "no_match":
		if c.ExpectEnforcement != nil {
			return fmt.Errorf("rule tests %q case %s: expect_enforcement requires expect: match", path, name)
		}
		if result.matched {
			return fmt.Errorf("rule tests %q case %s: expected no_match for %s", path, name, ruleID)
		}
	default:
		return fmt.Errorf("rule tests %q case %s: expect must be match or no_match", path, name)
	}
	return nil
}

type companionCaseResult struct {
	matched     bool
	enforcement bool
}

func companionCaseMatches(eng *rule.Engine, ruleID string, events []ruleTestEvent) (companionCaseResult, error) {
	var tracker *sequence.Tracker
	if seqs := eng.SequenceRules(); len(seqs) > 0 {
		tracker = sequence.NewTracker(seqs, sequence.DefaultConfig())
	}
	var result companionCaseResult
	for i, fixture := range events {
		ev := normalizeRuleTestEvent(fixture.Event, i)
		if err := ev.Validate(); err != nil {
			return result, fmt.Errorf("event %d: %w", i+1, err)
		}
		matches, err := eng.Eval(ev)
		if err != nil {
			return result, fmt.Errorf("event %d: %w", i+1, err)
		}
		for _, m := range matches {
			if m.Rule.ID == ruleID {
				result.matched = true
				result.enforcement = result.enforcement || m.EnforcementMatch
			}
		}
		observation, err := tracker.Observe(ev)
		if err != nil {
			return result, fmt.Errorf("event %d: %w", i+1, err)
		}
		for _, c := range observation.Findings {
			if c.Rule.ID == ruleID {
				result.matched = true
			}
		}
		for _, r := range observation.EnforcementRules {
			if r.ID == ruleID {
				result.enforcement = true
			}
		}
	}
	return result, nil
}

func normalizeRuleTestEvent(ev model.Event, index int) model.Event {
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = model.SchemaVersion
	}
	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("fixture-%d", index+1)
	}
	if ev.SourceAgent == "" {
		ev.SourceAgent = model.AgentUnknown
	}
	if ev.SourceType == "" {
		ev.SourceType = model.SourceArtifact
	}
	if ev.Confidence == "" {
		ev.Confidence = model.ConfidenceHigh
	}
	if ev.Evidence.ArtifactType == "" {
		ev.Evidence.ArtifactType = "rule_fixture"
	}
	if ev.SourceType == model.SourceArtifact && ev.Evidence.LocalPath == "" {
		ev.Evidence.LocalPath = "rule-fixture"
	}
	return ev.NormalizePaths()
}
