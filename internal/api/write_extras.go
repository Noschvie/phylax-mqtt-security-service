// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/audit"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/model"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/rules"
)

// Endpoints of PMSS v1 that are not part of the specification and not used
// by TasmoFleet (design 7.3): textname, enable/disable, single ACLs. Same
// steps as the other changes (write.go).

type patchClientReq struct {
	Textname *string `json:"textname"`
	// Textdescription is the marker of managed clients and cannot be
	// changed; the field exists only for a clear error.
	Textdescription *string `json:"textdescription"`
}

type removeACLReq struct {
	ACLType string `json:"acltype"`
	Topic   string `json:"topic"`
}

func (s *server) handlePatchClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	ev := audit.Event{Action: "modifyClient", Kind: "client", Name: name}
	var req patchClientReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	switch {
	case req.Textdescription != nil:
		s.fail(w, r, ev, validation(field("/textdescription", "read_only", "Field 'textdescription' is the marker of managed clients and cannot be changed.")))
		return
	case req.Textname == nil:
		s.fail(w, r, ev, validation(field("/textname", "required", "Field 'textname' is required.")))
		return
	}
	if msg := rules.CheckTextname(*req.Textname); msg != "" {
		s.fail(w, r, ev, validation(field("/textname", "invalid_text", "Field 'textname': "+msg+".")))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}
	if before.Textname == *req.Textname {
		s.respondClient(w, r, ev, before, before, http.StatusOK)
		return
	}
	cmd := dynsec.ModifyClient{Username: name, Textname: *req.Textname}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		c, err := s.getClient(ctx, name)
		return err == nil && c.Textname == cmd.Textname
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
		return
	}
	s.readClient(w, r, ev, before, http.StatusOK)
}

// handleEnable and handleDisable: DynSec checks disabled only at password
// logins. For certificate clients (CN=…) the request is refused with 409
// certificate_client, so a "locked" answer can never be wrong (decision on
// open point 8.8, variant A). Certificate clients are locked with DELETE
// and a new subject (SEC-20, SEC-23).
func (s *server) handleEnable(w http.ResponseWriter, r *http.Request)  { s.setDisabled(w, r, false) }
func (s *server) handleDisable(w http.ResponseWriter, r *http.Request) { s.setDisabled(w, r, true) }

func (s *server) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	name := r.PathValue("username")
	action := "enableClient"
	var cmd dynsec.Command = dynsec.EnableClient{Username: name}
	if disabled {
		action, cmd = "disableClient", dynsec.DisableClient{Username: name}
	}
	ev := audit.Event{Action: action, Kind: "client", Name: name}
	var empty struct{}
	if p := decodeBody(r, &empty, true); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	if rules.IsCertificateClient(name) {
		s.fail(w, r, ev, problem.New(problem.CertificateClient,
			"Certificate clients (CN=…) cannot be disabled: the broker checks 'disabled' only for password logins. Delete the client and issue a certificate with a new subject."))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}
	if before.Disabled == disabled {
		s.respondClient(w, r, ev, before, before, http.StatusOK)
		return
	}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		c, err := s.getClient(ctx, name)
		return err == nil && c.Disabled == disabled
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
		return
	}
	s.readClient(w, r, ev, before, http.StatusOK)
}

func (s *server) handleAddACL(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("role")
	ev := audit.Event{Action: "addRoleACL", Kind: "role", Name: name}
	var in rules.ACLInput
	if p := decodeBody(r, &in, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if !s.rolePathOK(w, r, ev, name) {
		return
	}
	checked, errs := rules.CheckACLs([]rules.ACLInput{in}, "")
	if len(errs) > 0 {
		for i := range errs {
			errs[i].Pointer = trimIndex(errs[i].Pointer)
		}
		s.fail(w, r, ev, validation(errs...))
		return
	}
	acl := checked[0]
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Role, error) { return s.getRole(ctx, name) },
		func(rl model.Role) string { return rl.ETag }, nil, "Role", name)
	if !ok {
		return
	}
	if slices.ContainsFunc(before.ACLs, func(a model.ACL) bool { return a.ACLType == acl.ACLType && a.Topic == acl.Topic }) {
		s.fail(w, r, ev, problem.New(problem.AlreadyExists,
			fmt.Sprintf("Role '%s' has an ACL with acltype '%s' and topic '%s' already; use PUT …/acls to change it.", name, acl.ACLType, acl.Topic)))
		return
	}
	want := append(slices.Clone(before.ACLs), model.ACL{ACLType: acl.ACLType, Topic: acl.Topic, Allow: acl.Allow, Priority: acl.Priority})
	model.SortACLs(want)
	cmd := dynsec.AddRoleACL{Rolename: name, ACLType: acl.ACLType, Topic: acl.Topic, Priority: acl.Priority, Allow: acl.Allow}
	s.changeACLs(w, r, ev, before, cmd, want)
}

func (s *server) handleRemoveACL(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("role")
	ev := audit.Event{Action: "removeRoleACL", Kind: "role", Name: name}
	var req removeACLReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if !s.rolePathOK(w, r, ev, name) {
		return
	}
	var errs []rules.FieldError
	if req.ACLType == "" {
		errs = append(errs, field("/acltype", "required", "Field 'acltype' is required."))
	}
	if req.Topic == "" {
		errs = append(errs, field("/topic", "required", "Field 'topic' is required."))
	}
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Role, error) { return s.getRole(ctx, name) },
		func(rl model.Role) string { return rl.ETag }, nil, "Role", name)
	if !ok {
		return
	}
	match := func(a model.ACL) bool { return a.ACLType == req.ACLType && a.Topic == req.Topic }
	if !slices.ContainsFunc(before.ACLs, match) {
		s.fail(w, r, ev, problem.New(problem.NotFound, fmt.Sprintf("Role '%s' has no ACL with acltype '%s' and topic '%s'.", name, req.ACLType, req.Topic)))
		return
	}
	want := slices.DeleteFunc(slices.Clone(before.ACLs), match)
	cmd := dynsec.RemoveRoleACL{Rolename: name, ACLType: req.ACLType, Topic: req.Topic}
	s.changeACLs(w, r, ev, before, cmd, want)
}

// changeACLs runs a single-ACL command, reads the role back and compares
// the whole list with the expected one (SEC-30).
func (s *server) changeACLs(w http.ResponseWriter, r *http.Request, ev audit.Event, before model.Role, cmd dynsec.Command, want []model.ACL) {
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		rl, err := s.getRole(ctx, before.Rolename)
		return err == nil && slices.Equal(rl.ACLs, want)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Role", before.Rolename))
		return
	}
	after, err := s.getRole(r.Context(), before.Rolename)
	if err != nil {
		ev.Before = before
		s.fail(w, r, ev, appliedButUnread(cmd, before.Rolename))
		return
	}
	if !slices.Equal(after.ACLs, want) {
		ev.Before, ev.After = before, after
		s.fail(w, r, ev, problem.New(problem.ReadbackMismatch, "The broker stored other ACLs than expected."))
		return
	}
	// Warnings refer to the ACL list of the response.
	s.respondRole(w, r, ev, &before, after, http.StatusOK, rules.DenyWarnings(fromModelACLs(after.ACLs), "/acls"))
}

func fromModelACLs(in []model.ACL) []rules.ACL {
	out := make([]rules.ACL, 0, len(in))
	for _, a := range in {
		out = append(out, rules.ACL{ACLType: a.ACLType, Topic: a.Topic, Allow: a.Allow, Priority: a.Priority})
	}
	return out
}

// trimIndex turns "/0/acltype" (from CheckACLs with an empty list pointer)
// into "/acltype" for a single ACL in the body.
func trimIndex(p string) string {
	if len(p) >= 2 && p[:2] == "/0" {
		return p[2:]
	}
	return p
}
