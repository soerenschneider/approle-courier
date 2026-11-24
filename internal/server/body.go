package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/soerenschneider/approle-courier/internal/api"
)

// requestBodies maps each route that takes a JSON body to its body type.
// The generated decoder ignores unknown fields; rejectUnknownFields checks
// them first, so a misspelled option fails instead of silently getting the
// default. A route missing here is not checked.
var requestBodies = map[string]func() any{
	"POST /v1/auth/challenge":                      func() any { return new(api.ChallengeRequest) },
	"POST /v1/approle/roles/{role_name}/secret-id": func() any { return new(api.CreateWrappedSecretIdRequest) },
}

// rejectUnknownFields answers 400 if the request body has fields its route's
// body type does not define, at any depth. It runs inside the mux, where
// r.Pattern is set, after authenticate and before the generated handler
// decodes the body.
func (s *Server) rejectUnknownFields(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newBody, ok := requestBodies[r.Pattern]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			s.requestError(w, r, err)
			return
		}
		if len(bytes.TrimSpace(b)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(newBody()); err != nil {
				// Sampled unless the caller is an authenticated machine.
				attrs := []any{"route", r.Pattern, "detail", truncate(err.Error(), maxAuditDetail)}
				machineID, authenticated := MachineID(r.Context())
				if authenticated {
					attrs = append(attrs, "machine_id", machineID)
				}
				s.audit(r.Context(), !authenticated, "invalid_body", attrs...)
				writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		next.ServeHTTP(w, r)
	})
}
