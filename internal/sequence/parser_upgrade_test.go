package sequence

import (
	"encoding/json"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

func TestStoreParserUpgradeInvalidatesVerdicts(t *testing.T) {
	enforce := true
	rules := compile(t, rule.Rule{
		ID: "test.parser_upgrade", Version: "1", Severity: model.SeverityHigh, Enforce: &enforce,
		Sequence: &rule.SequenceSpec{WithinEvents: 8, Steps: []rule.SequenceStep{
			{Expr: `shell_commands.exists(c, c.name == "echo")`},
			{Expr: `shell_commands.exists(c, c.name == "printf")`},
		}},
	})
	first := ev("first", "", model.EventCommandExec, nil)
	second := ev("second", "", model.EventCommandExec, func(e *model.Event) {
		e.ToolName, e.Command = "bash", "printf marker"
	})
	for _, tc := range []struct {
		revision string
		want     int
	}{
		{"sequence-projection-v6", 0},
		{"sequence-projection-v7", 0},
		{"sequence-projection-v8", 0},
		{sequenceProjectionRevision, 1},
	} {
		t.Run(tc.revision, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			db := openDB(t, path)
			_ = newStore(t, db, rules, DefaultConfig())
			// An older parser accepted a prefix while missing its dynamic tail.
			// These are the resulting persisted verdicts, not retained source.
			raw, err := json.Marshal(storedSession{
				RulesHash: fingerprintForProjection(rules, tc.revision),
				NextSeq:   1,
				Entries: []storedEntry{{
					Seq: 0, EventID: first.EventID, Evidence: first.Evidence,
					Confidence: first.Confidence, Masks: []uint8{1}, EnforcementMasks: []uint8{1},
				}},
				Rules: make([]storedRule, len(rules)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketSequence).Put([]byte(sessionKey(first)), raw)
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = openDB(t, path)
			defer db.Close()
			observation, err := newStore(t, db, rules, DefaultConfig()).Observe(second)
			if err != nil {
				t.Fatal(err)
			}
			if len(observation.Findings) != tc.want || len(observation.EnforcementRules) != tc.want {
				t.Fatalf("revision %s restored stale or lost current verdicts: %+v", tc.revision, observation)
			}
		})
	}
}
