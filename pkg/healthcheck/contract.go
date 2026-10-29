package healthcheck

import "encoding/json/v2"

// Outcome is the result of probing one cache node address.
type Outcome string

const (
	// OutcomePass, OutcomeWarn and OutcomeFail are the health service's own
	// answer, the others describe probes that got no usable answer.
	OutcomePass        Outcome = "pass"
	OutcomeWarn        Outcome = "warn"
	OutcomeFail        Outcome = "fail"
	OutcomeTimeout     Outcome = "timeout"
	OutcomeRefused     Outcome = "refused"
	OutcomeUnreachable Outcome = "unreachable"
	// OutcomeError is any other probe error, such as a reset connection, a
	// truncated answer or a local problem. It says nothing reliable about
	// the node, so it counts neither for nor against it.
	OutcomeError Outcome = "error"
	// OutcomeNeutral is an answer that can't be interpreted. The node and
	// the network are alive, so it counts neither for nor against the node.
	OutcomeNeutral Outcome = "neutral"
)

func (o Outcome) healthy() bool {
	return o == OutcomePass || o == OutcomeWarn
}

func (o Outcome) failed() bool {
	switch o {
	case OutcomeFail, OutcomeTimeout, OutcomeRefused, OutcomeUnreachable:
		return true
	default:
		return false
	}
}

// response is the /healthz body in the IETF health check format
// (draft-inadarei-api-health-check, media type application/health+json).
// Other fields, such as checks and output, are ignored.
type response struct {
	Status string `json:"status"`
}

// classifyResponse classifies a /healthz response. "pass" and "warn" need an
// HTTP 2xx/3xx status and "fail" a 4xx/5xx status. Anything else, including
// the aliases the draft allows, is neutral.
func classifyResponse(httpStatus int, body []byte) Outcome {
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		return OutcomeNeutral
	}

	switch resp.Status {
	case "pass":
		if httpStatus >= 200 && httpStatus < 400 {
			return OutcomePass
		}
	case "warn":
		if httpStatus >= 200 && httpStatus < 400 {
			return OutcomeWarn
		}
	case "fail":
		if httpStatus >= 400 && httpStatus < 600 {
			return OutcomeFail
		}
	}

	return OutcomeNeutral
}
