package model

import "testing"

func TestContentOmissionContract(t *testing.T) {
	for _, field := range []string{"content", "tool_input", "tool_result"} {
		event := validEvent(Event{EventType: EventToolResult, ContentOmitted: []string{field}})
		if field == "content" {
			event.EventType = EventMessageAssistant
			event.ContentBytes = 100
			event.ContentTruncated = true
		}
		if err := event.Validate(); err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		event.ContentOmitted = append(event.ContentOmitted, field)
		if err := event.Validate(); err == nil {
			t.Fatalf("duplicate %s omission accepted", field)
		}
	}
	for _, event := range []Event{
		{EventType: EventMessageAssistant, Content: "x", ContentBytes: 1, ContentOmitted: []string{"content"}},
		{EventType: EventToolResult, ToolResult: `"x"`, ContentOmitted: []string{"tool_result"}},
		{EventType: EventToolResult, ContentOmitted: []string{"content"}},
		{EventType: EventMessageAssistant, ContentOmitted: []string{"tool_result"}},
		{EventType: EventToolResult, ContentOmitted: []string{"command"}},
	} {
		if err := validEvent(event).Validate(); err == nil {
			t.Fatalf("invalid omission accepted: %+v", event)
		}
	}
}
