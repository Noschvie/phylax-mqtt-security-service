// SPDX-License-Identifier: AGPL-3.0-or-later

// Package problem writes error responses as application/problem+json
// (RFC 9457) with the error codes of the interface specification
// "MQTT Security Service API v1", section 3.5 (S-1).
//
// Clients evaluate only status and code. Each code belongs to exactly one
// status. detail is for display only and never contains passwords,
// password hashes or tokens (SEC-37).
package problem

import (
	"encoding/json"
	"net/http"
)

// Code is a machine-readable error code.
type Code string

// Error codes of the specification (section 3.5).
const (
	InvalidToken         Code = "invalid_token"
	InsufficientScope    Code = "insufficient_scope"
	NotManaged           Code = "not_managed"
	ReservedName         Code = "reserved_name"
	NotFound             Code = "not_found"
	AlreadyExists        Code = "already_exists"
	CertificateClient    Code = "certificate_client"
	PreconditionFailed   Code = "precondition_failed"
	PayloadTooLarge      Code = "payload_too_large"
	ValidationFailed     Code = "validation_failed"
	UnknownRole          Code = "unknown_role"
	UnknownGroup         Code = "unknown_group"
	PreconditionRequired Code = "precondition_required"
	ReadbackMismatch     Code = "readback_mismatch"
	BrokerError          Code = "broker_error"
	PartialFailure       Code = "partial_failure"
	BrokerUnavailable    Code = "broker_unavailable"
	BrokerTimeout        Code = "broker_timeout"

	// Not in the specification (yet); codes may be added within 1.x
	// (specification 3.4, 7).
	MethodNotAllowed Code = "method_not_allowed"
	InternalError    Code = "internal_error"
)

type codeInfo struct {
	status int
	title  string
}

var codes = map[Code]codeInfo{
	InvalidToken:         {http.StatusUnauthorized, "Missing or invalid bearer token"},
	InsufficientScope:    {http.StatusForbidden, "Token lacks the required scope"},
	NotManaged:           {http.StatusForbidden, "Object is not managed by the security service"},
	ReservedName:         {http.StatusForbidden, "Name is reserved"},
	NotFound:             {http.StatusNotFound, "Not found"},
	AlreadyExists:        {http.StatusConflict, "Object already exists"},
	CertificateClient:    {http.StatusConflict, "Certificate clients have no password"},
	PreconditionFailed:   {http.StatusPreconditionFailed, "Object has changed (If-Match)"},
	PayloadTooLarge:      {http.StatusRequestEntityTooLarge, "Request body too large"},
	ValidationFailed:     {http.StatusUnprocessableEntity, "Validation failed"},
	UnknownRole:          {http.StatusUnprocessableEntity, "Unknown or unmanaged role"},
	UnknownGroup:         {http.StatusUnprocessableEntity, "Unknown or unmanaged group"},
	PreconditionRequired: {http.StatusPreconditionRequired, "If-Match required"},
	ReadbackMismatch:     {http.StatusInternalServerError, "Broker state differs from the request"},
	BrokerError:          {http.StatusBadGateway, "Broker reported an error"},
	PartialFailure:       {http.StatusBadGateway, "Partial failure, compensation failed"},
	BrokerUnavailable:    {http.StatusServiceUnavailable, "Broker unavailable; nothing was sent"},
	BrokerTimeout:        {http.StatusGatewayTimeout, "Broker did not answer in time; state unknown"},
	MethodNotAllowed:     {http.StatusMethodNotAllowed, "Method not allowed"},
	InternalError:        {http.StatusInternalServerError, "Internal error"},
}

// TypeBase is the start of the type URI; the code is appended as anchor.
const TypeBase = "https://github.com/Noschvie/phylax-mqtt-security-service/blob/main/docs/errors.md#"

// Status returns the HTTP status of a code (500 for unknown codes).
func (c Code) Status() int {
	if info, ok := codes[c]; ok {
		return info.status
	}
	return http.StatusInternalServerError
}

// Title returns the fixed title of a code.
func (c Code) Title() string { return codes[c].title }

// FieldError is one entry of "errors" in a 422 response.
type FieldError struct {
	Pointer string `json:"pointer"` // JSON Pointer (RFC 6901) into the request body
	Code    string `json:"code"`
	Detail  string `json:"detail,omitempty"`
}

// Problem is a problem details object. Extra holds additional members,
// e.g. "compensated" or "clientExists" (specification 4.3).
type Problem struct {
	Code   Code
	Detail string
	Errors []FieldError
	Extra  map[string]any
	// WWWAuthenticate is sent as header with 401 and 403 insufficient_scope
	// (RFC 6750).
	WWWAuthenticate string
}

// New returns a problem with code and detail.
func New(code Code, detail string) *Problem { return &Problem{Code: code, Detail: detail} }

func (p *Problem) Error() string {
	if p.Detail != "" {
		return string(p.Code) + ": " + p.Detail
	}
	return string(p.Code)
}

// Write sends p for request r.
func Write(w http.ResponseWriter, r *http.Request, p *Problem) {
	body := map[string]any{}
	for k, v := range p.Extra {
		body[k] = v
	}
	status := p.Code.Status()
	body["type"] = TypeBase + string(p.Code)
	body["title"] = p.Code.Title()
	body["status"] = status
	body["code"] = p.Code
	if p.Detail != "" {
		body["detail"] = p.Detail
	}
	if r != nil {
		body["instance"] = r.URL.EscapedPath()
	}
	if len(p.Errors) > 0 {
		body["errors"] = p.Errors
	}

	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	h.Del("ETag")
	if p.WWWAuthenticate != "" {
		h.Set("WWW-Authenticate", p.WWWAuthenticate)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
