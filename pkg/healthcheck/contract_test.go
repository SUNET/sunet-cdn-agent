package healthcheck

import "testing"

func TestClassifyResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   Outcome
	}{
		{"pass", 200, `{"status":"pass"}`, OutcomePass},
		{"pass with other fields", 200, `{"status":"pass","version":"1.2.3","checks":{"haproxy:responseTime":[{"status":"fail"}]}}`, OutcomePass},
		{"warn", 200, `{"status":"warn"}`, OutcomeWarn},
		{"alias up", 200, `{"status":"up"}`, OutcomeNeutral},
		{"fail", 503, `{"status":"fail"}`, OutcomeFail},
		{"alias down", 503, `{"status":"down"}`, OutcomeNeutral},
		{"warn with 503", 503, `{"status":"warn"}`, OutcomeNeutral},
		{"fail with 200", 200, `{"status":"fail"}`, OutcomeNeutral},
		{"pass with 503", 503, `{"status":"pass"}`, OutcomeNeutral},
		{"unknown status", 200, `{"status":"drain"}`, OutcomeNeutral},
		{"no body", 502, ``, OutcomeNeutral},
		{"bad json", 200, `not json`, OutcomeNeutral},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyResponse(tt.status, []byte(tt.body)); got != tt.want {
				t.Errorf("classifyResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}
