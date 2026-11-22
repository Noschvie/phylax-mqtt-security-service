// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/rules"
)

// decodeBody reads a JSON object into v: unknown fields → 422 (S-1, 3.1),
// body above the limit → 413, empty body → 422 unless allowEmpty.
func decodeBody(r *http.Request, v any, allowEmpty bool) *problem.Problem {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return problem.New(problem.PayloadTooLarge, "Request body exceeds limits.maxRequestBytes")
	}
	if err != nil {
		return validation(rules.FieldError{Pointer: "", Code: "unreadable", Detail: "Request body could not be read."})
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if allowEmpty {
			return nil
		}
		return validation(rules.FieldError{Pointer: "", Code: "required", Detail: "Request body required."})
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return validation(jsonFieldError(err))
	}
	if dec.More() {
		return validation(rules.FieldError{Pointer: "", Code: "invalid_json", Detail: "Data after the JSON object."})
	}
	return nil
}

func jsonFieldError(err error) rules.FieldError {
	var (
		syntax *json.SyntaxError
		typ    *json.UnmarshalTypeError
	)
	switch {
	case errors.As(err, &syntax), errors.Is(err, io.ErrUnexpectedEOF):
		return rules.FieldError{Pointer: "", Code: "invalid_json", Detail: "Body is not valid JSON."}
	case errors.As(err, &typ):
		p := ""
		if typ.Field != "" {
			p = "/" + strings.ReplaceAll(typ.Field, ".", "/")
		}
		return rules.FieldError{Pointer: p, Code: "invalid_type", Detail: "Expected " + typ.Type.String() + "."}
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return rules.FieldError{Pointer: "/" + name, Code: "unknown_field", Detail: "Unknown field '" + name + "'."}
	default:
		return rules.FieldError{Pointer: "", Code: "invalid_json", Detail: "Body is not a valid JSON object."}
	}
}

// validation returns a 422 validation_failed with the field errors.
func validation(errs ...rules.FieldError) *problem.Problem {
	p := &problem.Problem{Code: problem.ValidationFailed}
	for _, e := range errs {
		p.Errors = append(p.Errors, problem.FieldError{Pointer: e.Pointer, Code: e.Code, Detail: e.Detail})
	}
	if len(errs) == 1 {
		p.Detail = errs[0].Detail
	} else {
		p.Detail = "Several fields are invalid."
	}
	return p
}

// field returns a single field error.
func field(pointer, code, detail string) rules.FieldError {
	return rules.FieldError{Pointer: pointer, Code: code, Detail: detail}
}

// escapePath encodes a name for a path segment as in the specification
// (CN=homeassistant,O=mqtt-apps → CN%3Dhomeassistant%2CO%3Dmqtt-apps).
func escapePath(name string) string {
	return strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}
