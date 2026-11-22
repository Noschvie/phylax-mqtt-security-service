// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"fmt"
	"slices"
)

// ACLInput is an ACL as sent by the caller; Allow and Priority are pointers
// to tell "missing" from false/0 (A-7: allow is required).
type ACLInput struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Allow    *bool  `json:"allow"`
	Priority *int   `json:"priority"`
}

// ACL is a checked ACL with the defaults filled in.
type ACL struct {
	ACLType  string
	Topic    string
	Allow    bool
	Priority int
}

// FieldError is a validation error with a JSON Pointer into the body.
type FieldError struct {
	Pointer string
	Code    string
	Detail  string
}

// Warning for the response (specification 3.6).
type Warning struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

// CheckACLs validates a full ACL list. pointer is the JSON Pointer of the
// list, e.g. "/acls". It returns the checked ACLs or field errors.
func CheckACLs(in []ACLInput, pointer string) ([]ACL, []FieldError) {
	var errs []FieldError
	out := make([]ACL, 0, len(in))
	seen := map[[2]string]int{}
	for i, a := range in {
		p := fmt.Sprintf("%s/%d", pointer, i)
		ok := true
		if a.ACLType == "" {
			errs = append(errs, FieldError{p + "/acltype", "required", "Field 'acltype' is required."})
			ok = false
		} else if !slices.Contains(ACLTypes, a.ACLType) {
			errs = append(errs, FieldError{p + "/acltype", "invalid_acltype", fmt.Sprintf("Unknown acltype '%s'.", a.ACLType)})
			ok = false
		}
		if msg := CheckTopicFilter(a.Topic); msg != "" {
			code := "invalid_topic"
			if a.Topic == "" {
				code = "required"
			}
			errs = append(errs, FieldError{p + "/topic", code, "Field 'topic': " + msg + "."})
			ok = false
		}
		if a.Allow == nil {
			errs = append(errs, FieldError{p + "/allow", "required", "Field 'allow' is required."})
			ok = false
		}
		prio := 0
		if a.Priority != nil {
			prio = *a.Priority
			if msg := CheckPriority(prio); msg != "" {
				errs = append(errs, FieldError{p + "/priority", "out_of_range", "Field 'priority' " + msg + "."})
				ok = false
			}
		}
		if !ok {
			continue
		}
		key := [2]string{a.ACLType, a.Topic}
		if j, dup := seen[key]; dup {
			errs = append(errs, FieldError{p, "duplicate_acl", fmt.Sprintf("Same acltype and topic as %s/%d.", pointer, j)})
			continue
		}
		seen[key] = i
		out = append(out, ACL{ACLType: a.ACLType, Topic: a.Topic, Allow: *a.Allow, Priority: prio})
	}
	return out, errs
}

// DenyWarnings returns a warning for every deny rule that does not have a
// higher priority than an overlapping allow rule of the same type: with
// equal priority the order is undefined (design 7.3, FILEDOWNLOAD case).
// Pointers refer to the positions in the request list.
func DenyWarnings(acls []ACL, pointer string) []Warning {
	warnings := []Warning{}
	for i, d := range acls {
		if d.Allow {
			continue
		}
		for _, a := range acls {
			if !a.Allow || a.ACLType != d.ACLType || a.Priority < d.Priority || !FiltersOverlap(a.Topic, d.Topic) {
				continue
			}
			warnings = append(warnings, Warning{
				Code:    "deny_priority_not_higher",
				Pointer: fmt.Sprintf("%s/%d", pointer, i),
				Detail: fmt.Sprintf("Deny rule for '%s' has priority %d, allow rule '%s' has %d; evaluation order is undefined.",
					d.Topic, d.Priority, a.Topic, a.Priority),
			})
			break
		}
	}
	return warnings
}
