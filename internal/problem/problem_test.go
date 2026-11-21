// SPDX-License-Identifier: AGPL-3.0-or-later

package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The status of every code is fixed by the specification (3.5).
func TestStatusOfCodes(t *testing.T) {
	want := map[Code]int{
		InvalidToken: 401, InsufficientScope: 403, NotManaged: 403, ReservedName: 403,
		NotFound: 404, AlreadyExists: 409, CertificateClient: 409, PreconditionFailed: 412,
		PayloadTooLarge: 413, ValidationFailed: 422, UnknownRole: 422, UnknownGroup: 422,
		PreconditionRequired: 428, ReadbackMismatch: 500, BrokerError: 502, PartialFailure: 502,
		BrokerUnavailable: 503, BrokerTimeout: 504,
	}
	for c, s := range want {
		if c.Status() != s {
			t.Errorf("%s: status %d, want %d", c, c.Status(), s)
		}
		if c.Title() == "" {
			t.Errorf("%s: no title", c)
		}
	}
	if Code("bogus").Status() != 500 {
		t.Error("unknown code is not 500")
	}
}

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("ETag", `"x"`)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/clients/CN%3Dha%2CO%3Dmqtt-apps", nil)
	Write(rec, r, &Problem{
		Code:            ValidationFailed,
		Detail:          "two errors",
		Errors:          []FieldError{{Pointer: "/acls/1/allow", Code: "required"}},
		Extra:           map[string]any{"compensated": true, "status": 999},
		WWWAuthenticate: `Bearer error="invalid_token"`,
	})

	if rec.Code != 422 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type %q", ct)
	}
	if rec.Header().Get("ETag") != "" || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("headers %v", rec.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != float64(422) || body["code"] != "validation_failed" || body["title"] != "Validation failed" ||
		body["instance"] != "/api/v1/clients/CN%3Dha%2CO%3Dmqtt-apps" || body["compensated"] != true ||
		body["type"] != TypeBase+"validation_failed" {
		t.Errorf("body %v", body)
	}
	errs, _ := body["errors"].([]any)
	if len(errs) != 1 {
		t.Errorf("errors %v", body["errors"])
	}
}
