package hook

import (
	"slices"
	"strings"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
)

// DecisionObservation reuses normalized tool evidence and the existing host
// lifecycle mapping. Host-specific details only establish capture boundaries.
func DecisionObservation(rawEvent string, lc Lifecycle, agent string, events []model.Event, payload map[string]any, content string) (decision.Observation, bool) {
	if len(events) == 0 {
		return decision.Observation{}, false
	}
	ev := events[len(events)-1]
	r := newResolver(agent, payload)
	name := strings.ToLower(r.hookEventName())
	if name == "" {
		name = strings.ToLower(rawEvent)
	}
	phase := ""
	switch {
	case lc == LifecycleSessionStart:
		phase = "start"
	case lc == LifecycleSessionEnd:
		phase = "end"
	case lc == LifecyclePermissionDenied:
		phase = "denied"
	case strings.HasSuffix(string(lc), "pre-tool"),
		EnforceEligible(agent, r.hookEventName(), lc):
		phase = "pre"
	case strings.Contains(string(lc), "post-tool"), lc == LifecycleCommandResult:
		phase = "result"
		if slices.Contains(ev.Tags, model.TagToolError) {
			phase = "failed"
		}
	case lc == LifecycleCommandExec, lc == LifecycleFileRead, lc == LifecycleFileWrite, lc == LifecycleMCPCall:
		phase = "pre"
	default:
		return decision.Observation{}, false
	}
	childBoundary := func(s string) bool {
		s = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(s))
		return s == "subagentstart" || s == "subagentstop"
	}
	if childBoundary(name) || childBoundary(rawEvent) {
		phase = "gap"
	}
	if name != "" {
		if resolved, err := ResolveLifecycle(agent, name); err != nil || resolved != lc {
			phase = "gap"
		}
	}
	// Claude omits agent_id for the main agent. A present invalid marker cannot
	// be interpreted as main-agent evidence (the mapping contract is unchanged).
	if agent == AgentClaude && ev.SubAgentID == "" {
		if _, present := payload["agent_id"]; present || name == "subagentstart" || name == "subagentstop" {
			phase = "gap"
		}
		// Refuse contradictory native/installed lifecycle names.
		if lc == LifecyclePreTool && name != "pretooluse" {
			phase = "gap"
		}
		if lc == LifecycleSessionEnd && name == "" {
			return decision.Observation{}, false
		}
	}
	o := decision.ProjectBatch(events, phase, content)
	parent := o.Subject
	switch {
	case agent == AgentClaude && ev.SubAgentID != "":
		parent.SubAgentID = ""
		o.Parent = &parent
	case agent == AgentCodex && ev.SubAgentID != "" && r.envelopeSessionID() != "":
		parent.Session, parent.SessionTree, parent.SubAgentID = r.envelopeSessionID(), "", ""
		o.Parent = &parent
	case agent == AgentHermes && (name == "subagent_start" || name == "subagent_stop") && r.envelopeSessionID() != "":
		parent.Session = r.envelopeSessionID()
		o.Parent = &parent
	case agent == AgentOpenClaw:
		if id, ok := payload["parent_session_id"].(string); ok && id != "" {
			parent.Session = id
			o.Parent = &parent
		}
	}
	if input, ok := r.toolInputValue().(map[string]any); ok && input["run_in_background"] == true {
		o.HistoryGap = true
	}
	if phase == "start" && ev.SubAgentID == "" && o.Parent == nil {
		switch agent {
		case AgentClaude, AgentCodex:
			o.NewSession = payload["source"] == "startup"
		case AgentCline:
			_, taskStart := payload["taskStart"].(map[string]any)
			_, taskResume := payload["taskResume"]
			o.NewSession = !taskResume && name != "taskresume" &&
				(name == "taskstart" || name == "task_start" || taskStart)
		case AgentOpenCode:
			// The generated plugin emits this only for session.created.
			o.NewSession = name == "session-start"
		case AgentOpenClaw:
			resumed, present := payload["resumed_from"]
			_, delegated := payload["parent_session_id"]
			o.NewSession = !delegated && (!present || resumed == "")
		}
	}
	if phase == "gap" {
		o.Complete = false
	}
	return o, true
}
