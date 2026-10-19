package decision

import (
	"encoding/json"
	"errors"
	"fmt"
)

const maxContextCalls = 4096

// ContextLimits bounds retained joined call/outcome entries, not event count.
type ContextLimits struct {
	MaxSessions int `yaml:"max_sessions" json:"max_sessions"`
	MaxCalls    int `yaml:"max_calls" json:"max_calls"`
	MaxBytes    int `yaml:"max_bytes" json:"max_bytes"`
	IdleTTLMS   int `yaml:"idle_ttl_ms" json:"idle_ttl_ms"`
}

func (s ContextLimits) Validate() error {
	if s.MaxSessions < 1 || s.MaxSessions > 4096 {
		return errors.New("max_sessions must be between 1 and 4096")
	}
	if s.MaxCalls < 1 || s.MaxCalls > maxContextCalls {
		return fmt.Errorf("max_calls must be between 1 and %d", maxContextCalls)
	}
	if s.MaxBytes < 1024 || s.MaxBytes > 256<<20 {
		return errors.New("max_bytes must be between 1024 and 268435456")
	}
	if s.IdleTTLMS < 1000 || s.IdleTTLMS > 24*60*60*1000 {
		return errors.New("idle_ttl_ms must be between 1000 and 86400000")
	}
	return nil
}

// Observation is an adapter-derived lifecycle event, never a provider claim.
// A missing Result differs from an observed JSON null.
type Observation struct {
	Subject    Subject
	Phase      string
	NewSession bool
	Action     json.RawMessage
	Result     json.RawMessage
	Complete   bool
}
