// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/audit"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/model"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/rules"
)

// Changing endpoints (specification 4.3–4.8; design 7.3, 7.4, A-5, A-8,
// A-9). Order of the checks in every handler:
//
//  1. names in path and body: reserved → 403, unmanaged → 403, invalid → 422
//  2. If-Match present → else 428
//  3. read the object → 404; managed (clients) → 403; ETag → 412
//  4. one DynSec command; no answer → read back (S-13): target reached →
//     success, otherwise 504; never resent
//  5. read back for the response and the new ETag; audit before/after
//
// Nothing is sent to the broker before all checks have passed.

// --- request bodies ---

type roleAssignReq struct {
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority"`
}

type groupAssignReq struct {
	Groupname string `json:"groupname"`
	Priority  *int   `json:"priority"`
}

type createClientReq struct {
	Username string           `json:"username"`
	Textname *string          `json:"textname"`
	Password *string          `json:"password"`
	Roles    []roleAssignReq  `json:"roles"`
	Groups   []groupAssignReq `json:"groups"`
}

type passwordReq struct {
	Password *string `json:"password"`
}

type groupClientReq struct {
	Username string `json:"username"`
}

type createGroupReq struct {
	Groupname string  `json:"groupname"`
	Textname  *string `json:"textname"`
}

type createRoleReq struct {
	Rolename string           `json:"rolename"`
	Textname *string          `json:"textname"`
	ACLs     []rules.ACLInput `json:"acls"`
}

type aclsReq struct {
	ACLs *[]rules.ACLInput `json:"acls"`
}

// --- responses ---

type clientChange struct {
	clientView
	Warnings []rules.Warning `json:"warnings"`
}

type groupChange struct {
	groupView
	Warnings []rules.Warning `json:"warnings"`
}

type roleChange struct {
	roleView
	Warnings []rules.Warning `json:"warnings"`
}

type createClientResp struct {
	Client            clientView      `json:"client"`
	Password          string          `json:"password,omitempty"`
	PasswordGenerated bool            `json:"passwordGenerated"`
	Warnings          []rules.Warning `json:"warnings"`
}

type passwordResp struct {
	Username          string `json:"username"`
	Password          string `json:"password,omitempty"`
	PasswordGenerated bool   `json:"passwordGenerated"`
}

var noWarnings = []rules.Warning{}

// --- clients ---

func (s *server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{Action: "createClient", Kind: "client"}
	var req createClientReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	ev.Name = req.Username
	if rules.IsReservedClient(req.Username) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	cert := rules.IsCertificateClient(req.Username)
	var errs []rules.FieldError
	if msg := rules.CheckUsername(req.Username); msg != "" {
		errs = append(errs, field("/username", "invalid_name", "Field 'username': "+msg+"."))
	}
	if req.Textname != nil {
		if msg := rules.CheckTextname(*req.Textname); msg != "" {
			errs = append(errs, field("/textname", "invalid_text", "Field 'textname': "+msg+"."))
		}
	}
	if req.Password != nil {
		if cert {
			errs = append(errs, field("/password", "certificate_client", "Certificate clients (CN=…) have no password."))
		} else if msg := rules.CheckPassword(*req.Password); msg != "" {
			errs = append(errs, field("/password", "invalid_password", "Field 'password': "+msg+"."))
		}
	}
	roles, rerrs, rp := s.checkRoleAssignments(req.Roles, "/roles")
	groups, gerrs, gp := s.checkGroupAssignments(req.Groups, "/groups")
	errs = append(append(errs, rerrs...), gerrs...)
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	if p := cmp(rp, gp); p != nil {
		p.Extra = map[string]any{"clientExists": false}
		s.fail(w, r, ev, p)
		return
	}

	password, generated := "", false
	if !cert {
		if req.Password != nil {
			password = *req.Password
		} else {
			var err error
			if password, err = rules.GeneratePassword(); err != nil {
				s.fail(w, r, ev, problem.New(problem.InternalError, "Password generation failed."))
				return
			}
			generated = true
		}
	}

	cmd := dynsec.CreateClient{
		Username: req.Username, Password: password, Textname: deref(req.Textname),
		Textdescription: s.opts.Managed.ClientMarker, Roles: roles, Groups: groups,
	}
	reached := func(c model.Client) bool {
		return s.marks.ClientManaged(c) && c.Textname == cmd.Textname && sameRoles(c.Roles, roles) && sameGroups(c.Groups, groups)
	}
	err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		c, err := s.getClient(ctx, req.Username)
		return err == nil && reached(c)
	})
	if err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", req.Username))
		return
	}

	c, err := s.getClient(r.Context(), req.Username)
	if err != nil {
		s.fail(w, r, ev, appliedButUnread(cmd, req.Username))
		return
	}
	if !reached(c) {
		// Should not happen: createClient is atomic. Compensate (A-8).
		p := problem.New(problem.ReadbackMismatch, "The created client differs from the request.")
		p.Extra = map[string]any{"compensated": true, "clientExists": false}
		ev.After = c
		if derr := s.run(r.Context(), dynsec.DeleteClient{Username: req.Username}, nil); derr != nil {
			p = problem.New(problem.PartialFailure, "The created client differs from the request and could not be deleted again.")
			p.Extra = map[string]any{"compensated": false, "clientExists": true}
		}
		s.fail(w, r, ev, p)
		return
	}

	ev.Result, ev.After = audit.ResultSuccess, c
	s.audit.Record(r.Context(), ev)
	w.Header().Set("Location", "/api/v1/clients/"+escapePath(c.Username))
	w.Header().Set("ETag", c.ETag)
	writeJSON(w, http.StatusCreated, createClientResp{
		Client: clientView{c, true}, Password: generatedOrEmpty(password, generated),
		PasswordGenerated: generated, Warnings: noWarnings,
	})
}

func (s *server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	ev := audit.Event{Action: "setClientPassword", Kind: "client", Name: name}
	var req passwordReq
	if p := decodeBody(r, &req, true); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	if rules.IsCertificateClient(name) {
		s.fail(w, r, ev, problem.New(problem.CertificateClient, "Certificate clients (CN=…) have no password."))
		return
	}
	if req.Password != nil {
		if msg := rules.CheckPassword(*req.Password); msg != "" {
			s.fail(w, r, ev, validation(field("/password", "invalid_password", "Field 'password': "+msg+".")))
			return
		}
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}

	password, generated := "", false
	if req.Password != nil {
		password = *req.Password
	} else {
		var err error
		if password, err = rules.GeneratePassword(); err != nil {
			s.fail(w, r, ev, problem.New(problem.InternalError, "Password generation failed."))
			return
		}
		generated = true
	}
	cmd := dynsec.SetClientPassword{Username: name, Password: password}
	// A password change cannot be read back (no hash in getClient, S-5):
	// without an answer the result is always 504 (S-13).
	if err := s.run(r.Context(), cmd, nil); err != nil {
		p := s.changeProblem(err, cmd, "Client", name)
		if p.Code == problem.BrokerTimeout {
			p.Detail = fmt.Sprintf("No response to setClientPassword for '%s'. The password may or may not have been changed.", name)
		}
		s.fail(w, r, ev, p)
		return
	}
	ev.Result, ev.Before, ev.After = audit.ResultSuccess, before, before
	s.audit.Record(r.Context(), ev)
	w.Header().Set("ETag", before.ETag) // unchanged (S-5)
	writeJSON(w, http.StatusOK, passwordResp{Username: name, Password: generatedOrEmpty(password, generated), PasswordGenerated: generated})
}

func (s *server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	ev := audit.Event{Action: "deleteClient", Kind: "client", Name: name}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}
	cmd := dynsec.DeleteClient{Username: name}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool { return isNotFound(s.getClientErr(ctx, name)) }); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
		return
	}
	ev.Result, ev.Before = audit.ResultSuccess, before
	s.audit.Record(r.Context(), ev)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAddClientRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	ev := audit.Event{Action: "addClientRole", Kind: "client", Name: name}
	var req roleAssignReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	assign, errs, p := s.checkRoleAssignments([]roleAssignReq{req}, "")
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	if p != nil {
		s.fail(w, r, ev, p)
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}
	target := model.RoleRef{Rolename: req.Rolename, Priority: prioOr(req.Priority, model.DefaultAssignmentPriority)}
	if slices.Contains(before.Roles, target) {
		s.respondClient(w, r, ev, before, before, http.StatusOK) // already in place
		return
	}
	cmd := dynsec.AddClientRole{Username: name, Rolename: req.Rolename, Priority: assign[0].Priority}
	if hasRole(before.Roles, req.Rolename) {
		// DynSec refuses a second assignment; change the priority by
		// removing and adding (two commands, not atomic).
		if err := s.run(r.Context(), dynsec.RemoveClientRole{Username: name, Rolename: req.Rolename}, nil); err != nil {
			s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
			return
		}
	}
	err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		c, err := s.getClient(ctx, name)
		return err == nil && slices.Contains(c.Roles, target)
	})
	if err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
		return
	}
	s.readClient(w, r, ev, before, http.StatusOK)
}

func (s *server) handleRemoveClientRole(w http.ResponseWriter, r *http.Request) {
	name, role := r.PathValue("username"), r.PathValue("role")
	ev := audit.Event{Action: "removeClientRole", Kind: "client", Name: name}
	if rules.IsReservedClient(name) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Client, error) { return s.getClient(ctx, name) },
		func(c model.Client) string { return c.ETag }, s.marks.ClientManaged, "Client", name)
	if !ok {
		return
	}
	if !hasRole(before.Roles, role) {
		s.fail(w, r, ev, problem.New(problem.NotFound, fmt.Sprintf("Role '%s' is not assigned to client '%s'.", role, name)))
		return
	}
	cmd := dynsec.RemoveClientRole{Username: name, Rolename: role}
	err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		c, err := s.getClient(ctx, name)
		return err == nil && !hasRole(c.Roles, role)
	})
	if err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Client", name))
		return
	}
	s.readClient(w, r, ev, before, http.StatusNoContent)
}

// readClient reads the client back and answers with it (or 204 with the
// ETag header).
func (s *server) readClient(w http.ResponseWriter, r *http.Request, ev audit.Event, before model.Client, status int) {
	after, err := s.getClient(r.Context(), before.Username)
	if err != nil {
		ev.Before = before
		s.fail(w, r, ev, appliedButUnread(dynsec.GetClient{}, before.Username))
		return
	}
	s.respondClient(w, r, ev, before, after, status)
}

func (s *server) respondClient(w http.ResponseWriter, r *http.Request, ev audit.Event, before, after model.Client, status int) {
	ev.Result, ev.Before, ev.After = audit.ResultSuccess, before, after
	s.audit.Record(r.Context(), ev)
	w.Header().Set("ETag", after.ETag)
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, clientChange{clientView{after, s.marks.ClientManaged(after)}, noWarnings})
}

// --- groups ---

func (s *server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{Action: "createGroup", Kind: "group"}
	var req createGroupReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	ev.Name = req.Groupname
	var errs []rules.FieldError
	if msg := rules.CheckObjectName(req.Groupname, s.opts.Managed.GroupPrefix); msg != "" {
		errs = append(errs, field("/groupname", "invalid_name", "Field 'groupname': "+msg+"."))
	}
	if req.Textname != nil {
		if msg := rules.CheckTextname(*req.Textname); msg != "" {
			errs = append(errs, field("/textname", "invalid_text", "Field 'textname': "+msg+"."))
		}
	}
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	cmd := dynsec.CreateGroup{Groupname: req.Groupname, Textname: deref(req.Textname)}
	err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		g, err := s.getGroup(ctx, req.Groupname)
		return err == nil && g.Textname == cmd.Textname
	})
	if err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", req.Groupname))
		return
	}
	g, err := s.getGroup(r.Context(), req.Groupname)
	if err != nil {
		s.fail(w, r, ev, appliedButUnread(cmd, req.Groupname))
		return
	}
	w.Header().Set("Location", "/api/v1/groups/"+escapePath(g.Groupname))
	s.respondGroup(w, r, ev, nil, g, http.StatusCreated)
}

func (s *server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("group")
	ev := audit.Event{Action: "deleteGroup", Kind: "group", Name: name}
	if !s.groupPathOK(w, r, ev, name) {
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Group, error) { return s.getGroup(ctx, name) },
		func(g model.Group) string { return g.ETag }, nil, "Group", name)
	if !ok {
		return
	}
	cmd := dynsec.DeleteGroup{Groupname: name}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		_, err := s.getGroup(ctx, name)
		return isNotFound(err)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
		return
	}
	ev.Result, ev.Before = audit.ResultSuccess, before
	s.audit.Record(r.Context(), ev)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAddGroupClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("group")
	ev := audit.Event{Action: "addGroupClient", Kind: "group", Name: name}
	var req groupClientReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if !s.groupPathOK(w, r, ev, name) {
		return
	}
	if req.Username == "" {
		s.fail(w, r, ev, validation(field("/username", "required", "Field 'username' is required.")))
		return
	}
	if rules.IsReservedClient(req.Username) {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Names starting with 'pmss-' are reserved."))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Group, error) { return s.getGroup(ctx, name) },
		func(g model.Group) string { return g.ETag }, nil, "Group", name)
	if !ok {
		return
	}
	// Assignments only between managed objects (design 7.3).
	c, err := s.getClient(r.Context(), req.Username)
	switch {
	case isNotFound(err) || (err == nil && !s.marks.ClientManaged(c)):
		s.fail(w, r, ev, validation(field("/username", "unknown_client", fmt.Sprintf("Client '%s' does not exist or is not managed.", req.Username))))
		return
	case err != nil:
		s.fail(w, r, ev, s.readProblem(err))
		return
	}
	member := model.ClientRef{Username: req.Username}
	if slices.Contains(before.Clients, member) {
		s.respondGroup(w, r, ev, &before, before, http.StatusOK)
		return
	}
	cmd := dynsec.AddGroupClient{Groupname: name, Username: req.Username}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		g, err := s.getGroup(ctx, name)
		return err == nil && slices.Contains(g.Clients, member)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
		return
	}
	s.readGroup(w, r, ev, before, http.StatusOK)
}

func (s *server) handleRemoveGroupClient(w http.ResponseWriter, r *http.Request) {
	name, username := r.PathValue("group"), r.PathValue("username")
	ev := audit.Event{Action: "removeGroupClient", Kind: "group", Name: name}
	if !s.groupPathOK(w, r, ev, name) {
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Group, error) { return s.getGroup(ctx, name) },
		func(g model.Group) string { return g.ETag }, nil, "Group", name)
	if !ok {
		return
	}
	member := model.ClientRef{Username: username}
	if !slices.Contains(before.Clients, member) {
		s.fail(w, r, ev, problem.New(problem.NotFound, fmt.Sprintf("Client '%s' is not in group '%s'.", username, name)))
		return
	}
	cmd := dynsec.RemoveGroupClient{Groupname: name, Username: username}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		g, err := s.getGroup(ctx, name)
		return err == nil && !slices.Contains(g.Clients, member)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
		return
	}
	s.readGroup(w, r, ev, before, http.StatusNoContent)
}

func (s *server) handleAddGroupRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("group")
	ev := audit.Event{Action: "addGroupRole", Kind: "group", Name: name}
	var req roleAssignReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if !s.groupPathOK(w, r, ev, name) {
		return
	}
	assign, errs, p := s.checkRoleAssignments([]roleAssignReq{req}, "")
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	if p != nil {
		s.fail(w, r, ev, p)
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Group, error) { return s.getGroup(ctx, name) },
		func(g model.Group) string { return g.ETag }, nil, "Group", name)
	if !ok {
		return
	}
	target := model.RoleRef{Rolename: req.Rolename, Priority: prioOr(req.Priority, model.DefaultAssignmentPriority)}
	if slices.Contains(before.Roles, target) {
		s.respondGroup(w, r, ev, &before, before, http.StatusOK)
		return
	}
	cmd := dynsec.AddGroupRole{Groupname: name, Rolename: req.Rolename, Priority: assign[0].Priority}
	if hasRole(before.Roles, req.Rolename) {
		if err := s.run(r.Context(), dynsec.RemoveGroupRole{Groupname: name, Rolename: req.Rolename}, nil); err != nil {
			s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
			return
		}
	}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		g, err := s.getGroup(ctx, name)
		return err == nil && slices.Contains(g.Roles, target)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
		return
	}
	s.readGroup(w, r, ev, before, http.StatusOK)
}

func (s *server) handleRemoveGroupRole(w http.ResponseWriter, r *http.Request) {
	name, role := r.PathValue("group"), r.PathValue("role")
	ev := audit.Event{Action: "removeGroupRole", Kind: "group", Name: name}
	if !s.groupPathOK(w, r, ev, name) {
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Group, error) { return s.getGroup(ctx, name) },
		func(g model.Group) string { return g.ETag }, nil, "Group", name)
	if !ok {
		return
	}
	if !hasRole(before.Roles, role) {
		s.fail(w, r, ev, problem.New(problem.NotFound, fmt.Sprintf("Role '%s' is not assigned to group '%s'.", role, name)))
		return
	}
	cmd := dynsec.RemoveGroupRole{Groupname: name, Rolename: role}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		g, err := s.getGroup(ctx, name)
		return err == nil && !hasRole(g.Roles, role)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Group", name))
		return
	}
	s.readGroup(w, r, ev, before, http.StatusNoContent)
}

func (s *server) groupPathOK(w http.ResponseWriter, r *http.Request, ev audit.Event, name string) bool {
	if !s.marks.GroupManaged(name) {
		s.fail(w, r, ev, problem.New(problem.NotManaged, fmt.Sprintf("Group '%s' has no prefix '%s'.", name, s.opts.Managed.GroupPrefix)))
		return false
	}
	return true
}

func (s *server) readGroup(w http.ResponseWriter, r *http.Request, ev audit.Event, before model.Group, status int) {
	after, err := s.getGroup(r.Context(), before.Groupname)
	if err != nil {
		ev.Before = before
		s.fail(w, r, ev, appliedButUnread(dynsec.GetGroup{}, before.Groupname))
		return
	}
	s.respondGroup(w, r, ev, &before, after, status)
}

func (s *server) respondGroup(w http.ResponseWriter, r *http.Request, ev audit.Event, before *model.Group, after model.Group, status int) {
	ev.Result, ev.After = audit.ResultSuccess, after
	if before != nil {
		ev.Before = *before
	}
	s.audit.Record(r.Context(), ev)
	w.Header().Set("ETag", after.ETag)
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, groupChange{groupView{after, true}, noWarnings})
}

// --- roles ---

func (s *server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{Action: "createRole", Kind: "role"}
	var req createRoleReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	ev.Name = req.Rolename
	if req.Rolename == rules.ReservedRole {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Role 'role_security_manager' is reserved."))
		return
	}
	var errs []rules.FieldError
	if msg := rules.CheckObjectName(req.Rolename, s.opts.Managed.RolePrefix); msg != "" {
		errs = append(errs, field("/rolename", "invalid_name", "Field 'rolename': "+msg+"."))
	}
	if req.Textname != nil {
		if msg := rules.CheckTextname(*req.Textname); msg != "" {
			errs = append(errs, field("/textname", "invalid_text", "Field 'textname': "+msg+"."))
		}
	}
	acls, aerrs := rules.CheckACLs(req.ACLs, "/acls")
	errs = append(errs, aerrs...)
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	cmd := dynsec.CreateRole{Rolename: req.Rolename, Textname: deref(req.Textname), ACLs: toDynsecACLs(acls)}
	want := toModelACLs(acls)
	reached := func(rl model.Role) bool { return rl.Textname == cmd.Textname && slices.Equal(rl.ACLs, want) }
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		rl, err := s.getRole(ctx, req.Rolename)
		return err == nil && reached(rl)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Role", req.Rolename))
		return
	}
	rl, err := s.getRole(r.Context(), req.Rolename)
	if err != nil {
		s.fail(w, r, ev, appliedButUnread(cmd, req.Rolename))
		return
	}
	if !reached(rl) {
		// S-6: read-back differs → delete the role again (A-8).
		ev.After = rl
		p := problem.New(problem.ReadbackMismatch, "The broker stored other ACLs than requested; the role was deleted again.")
		p.Extra = map[string]any{"compensated": true, "roleExists": false}
		if derr := s.run(r.Context(), dynsec.DeleteRole{Rolename: req.Rolename}, nil); derr != nil {
			p = problem.New(problem.PartialFailure, "The broker stored other ACLs than requested and the role could not be deleted again.")
			p.Extra = map[string]any{"compensated": false, "roleExists": true}
		}
		s.fail(w, r, ev, p)
		return
	}
	w.Header().Set("Location", "/api/v1/roles/"+escapePath(rl.Rolename))
	s.respondRole(w, r, ev, nil, rl, http.StatusCreated, rules.DenyWarnings(acls, "/acls"))
}

func (s *server) handleReplaceACLs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("role")
	ev := audit.Event{Action: "replaceACLs", Kind: "role", Name: name}
	var req aclsReq
	if p := decodeBody(r, &req, false); p != nil {
		s.fail(w, r, ev, p)
		return
	}
	if !s.rolePathOK(w, r, ev, name) {
		return
	}
	if req.ACLs == nil {
		s.fail(w, r, ev, validation(field("/acls", "required", "Field 'acls' is required (an empty list removes all rules).")))
		return
	}
	acls, errs := rules.CheckACLs(*req.ACLs, "/acls")
	if len(errs) > 0 {
		s.fail(w, r, ev, validation(errs...))
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Role, error) { return s.getRole(ctx, name) },
		func(rl model.Role) string { return rl.ETag }, nil, "Role", name)
	if !ok {
		return
	}
	want := toModelACLs(acls)
	cmd := dynsec.ModifyRole{Rolename: name, ACLs: toDynsecACLs(acls)}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		rl, err := s.getRole(ctx, name)
		return err == nil && slices.Equal(rl.ACLs, want)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Role", name))
		return
	}
	after, err := s.getRole(r.Context(), name)
	if err != nil {
		ev.Before = before
		s.fail(w, r, ev, appliedButUnread(cmd, name))
		return
	}
	if !slices.Equal(after.ACLs, want) {
		// SEC-30: DynSec dropped or changed entries silently.
		ev.Before, ev.After = before, after
		s.fail(w, r, ev, problem.New(problem.ReadbackMismatch, "The broker stored other ACLs than requested."))
		return
	}
	s.respondRole(w, r, ev, &before, after, http.StatusOK, rules.DenyWarnings(acls, "/acls"))
}

func (s *server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("role")
	ev := audit.Event{Action: "deleteRole", Kind: "role", Name: name}
	if !s.rolePathOK(w, r, ev, name) {
		return
	}
	before, ok := precondition(s, w, r, &ev, func(ctx context.Context) (model.Role, error) { return s.getRole(ctx, name) },
		func(rl model.Role) string { return rl.ETag }, nil, "Role", name)
	if !ok {
		return
	}
	cmd := dynsec.DeleteRole{Rolename: name}
	if err := s.run(r.Context(), cmd, func(ctx context.Context) bool {
		_, err := s.getRole(ctx, name)
		return isNotFound(err)
	}); err != nil {
		s.fail(w, r, ev, s.changeProblem(err, cmd, "Role", name))
		return
	}
	ev.Result, ev.Before = audit.ResultSuccess, before
	s.audit.Record(r.Context(), ev)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) rolePathOK(w http.ResponseWriter, r *http.Request, ev audit.Event, name string) bool {
	if name == rules.ReservedRole {
		s.fail(w, r, ev, problem.New(problem.ReservedName, "Role 'role_security_manager' is reserved."))
		return false
	}
	if !s.marks.RoleManaged(name) {
		s.fail(w, r, ev, problem.New(problem.NotManaged, fmt.Sprintf("Role '%s' has no prefix '%s'.", name, s.opts.Managed.RolePrefix)))
		return false
	}
	return true
}

func (s *server) respondRole(w http.ResponseWriter, r *http.Request, ev audit.Event, before *model.Role, after model.Role, status int, warnings []rules.Warning) {
	ev.Result, ev.After = audit.ResultSuccess, after
	if before != nil {
		ev.Before = *before
	}
	s.audit.Record(r.Context(), ev)
	w.Header().Set("ETag", after.ETag)
	writeJSON(w, status, roleChange{roleView{after, true}, warnings})
}

// --- shared steps ---

// precondition reads the object in the path and checks If-Match (A-5):
// missing → 428, object missing → 404, not managed → 403, other ETag → 412.
// managed may be nil when the name already decided it (roles, groups).
func precondition[T any](s *server, w http.ResponseWriter, r *http.Request, ev *audit.Event,
	load func(context.Context) (T, error), etagOf func(T) string, managed func(T) bool, kind, name string) (T, bool) {
	var zero T
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		s.fail(w, r, *ev, problem.New(problem.PreconditionRequired, "Send the ETag of the object in If-Match."))
		return zero, false
	}
	obj, err := load(r.Context())
	if err != nil {
		if isNotFound(err) {
			s.fail(w, r, *ev, problem.New(problem.NotFound, fmt.Sprintf("%s '%s' does not exist.", kind, name)))
		} else {
			s.fail(w, r, *ev, s.readProblem(err))
		}
		return zero, false
	}
	if managed != nil && !managed(obj) {
		s.fail(w, r, *ev, problem.New(problem.NotManaged, fmt.Sprintf("%s '%s' has no '%s' marker.", kind, name, s.opts.Managed.ClientMarker)))
		return zero, false
	}
	if strings.TrimSpace(ifMatch) != etagOf(obj) {
		ev.Before = obj
		s.fail(w, r, *ev, problem.New(problem.PreconditionFailed, fmt.Sprintf("%s '%s' has changed; read it again.", kind, name)))
		return zero, false
	}
	return obj, true
}

// run executes one changing command. Without an answer it reads back
// (S-13): if reached reports the target state, the change counts as done.
// Commands are never resent (A-9).
func (s *server) run(ctx context.Context, cmd dynsec.Command, reached func(context.Context) bool) error {
	if s.opts.DynSec == nil {
		return errNoDynSec
	}
	_, err := s.opts.DynSec.Execute(ctx, cmd)
	if errors.Is(err, dynsec.ErrTimeout) && reached != nil {
		if reached(context.WithoutCancel(ctx)) {
			s.opts.Logger.Warn("no answer from the broker, but the change is in place", "command", cmd.CommandName())
			return nil
		}
	}
	return err
}

// changeProblem maps errors of a changing command (specification 3.5, 3.7).
func (s *server) changeProblem(err error, cmd dynsec.Command, kind, name string) *problem.Problem {
	var ce *dynsec.CommandError
	switch {
	case errors.Is(err, dynsec.ErrUnavailable), errors.Is(err, errNoDynSec):
		return problem.New(problem.BrokerUnavailable, "No connection to the broker; nothing was sent.")
	case errors.Is(err, dynsec.ErrTimeout), errors.Is(err, context.Canceled):
		return problem.New(problem.BrokerTimeout,
			fmt.Sprintf("No response to %s for '%s'. The change may or may not have been applied.", cmd.CommandName(), name))
	case errors.As(err, &ce):
		switch {
		case strings.HasPrefix(ce.Message, "Role not found"), strings.HasPrefix(ce.Message, "Group not found"):
			p := problem.New(problem.UnknownRole, "A role does not exist.")
			if strings.HasPrefix(ce.Message, "Group") {
				p = problem.New(problem.UnknownGroup, "A group does not exist.")
			}
			if _, create := cmd.(dynsec.CreateClient); create {
				// createClient is atomic: nothing was created (specification 4.3).
				p.Extra = map[string]any{"clientExists": false}
			}
			return p
		case ce.AlreadyExists():
			return problem.New(problem.AlreadyExists, fmt.Sprintf("%s '%s' already exists.", kind, name))
		case ce.NotFound():
			return problem.New(problem.NotFound, fmt.Sprintf("%s '%s' does not exist.", kind, name))
		}
		return problem.New(problem.BrokerError, ce.Command+": "+ce.Message)
	}
	return problem.New(problem.BrokerError, "Broker request failed.")
}

// readProblem maps errors of reading commands inside a change.
func (s *server) readProblem(err error) *problem.Problem {
	switch {
	case errors.Is(err, dynsec.ErrUnavailable), errors.Is(err, errNoDynSec):
		return problem.New(problem.BrokerUnavailable, "No connection to the broker; nothing was sent.")
	case errors.Is(err, dynsec.ErrTimeout), errors.Is(err, context.Canceled):
		// Nothing was changed yet, but the caller learns that by reading.
		return problem.New(problem.BrokerTimeout, "The broker did not answer in time; nothing was changed.")
	}
	return problem.New(problem.BrokerError, "Unexpected answer from the broker.")
}

// appliedButUnread: the change was confirmed, reading it back failed. The
// caller must read again (like 504).
func appliedButUnread(cmd dynsec.Command, name string) *problem.Problem {
	return problem.New(problem.BrokerTimeout,
		fmt.Sprintf("%s for '%s' was applied, but reading it back failed; read the object again.", cmd.CommandName(), name))
}

// fail answers with p and writes the audit record.
func (s *server) fail(w http.ResponseWriter, r *http.Request, ev audit.Event, p *problem.Problem) {
	ev.Code, ev.Detail = string(p.Code), p.Detail
	switch p.Code {
	case problem.BrokerTimeout:
		ev.Result = audit.ResultUnknown
	case problem.PartialFailure:
		ev.Result = audit.ResultPartial
	default:
		ev.Result = audit.ResultFailed
	}
	s.audit.Record(r.Context(), ev)
	problem.Write(w, r, p)
}

// checkRoleAssignments validates role assignments: reserved → 403,
// unmanaged → 422 unknown_role (existence is checked by the broker).
func (s *server) checkRoleAssignments(in []roleAssignReq, pointer string) ([]dynsec.RoleAssignment, []rules.FieldError, *problem.Problem) {
	var (
		out  []dynsec.RoleAssignment
		errs []rules.FieldError
		p    *problem.Problem
		seen = map[string]bool{}
	)
	for i, a := range in {
		ptr := pointer
		if pointer != "" {
			ptr = fmt.Sprintf("%s/%d", pointer, i)
		}
		switch {
		case a.Rolename == "":
			errs = append(errs, field(ptr+"/rolename", "required", "Field 'rolename' is required."))
			continue
		case seen[a.Rolename]:
			errs = append(errs, field(ptr+"/rolename", "duplicate", fmt.Sprintf("Role '%s' is listed twice.", a.Rolename)))
			continue
		}
		seen[a.Rolename] = true
		if a.Priority != nil {
			if msg := rules.CheckPriority(*a.Priority); msg != "" {
				errs = append(errs, field(ptr+"/priority", "out_of_range", "Field 'priority' "+msg+"."))
				continue
			}
		}
		switch {
		case a.Rolename == rules.ReservedRole:
			p = cmp(p, problem.New(problem.ReservedName, "Role 'role_security_manager' is reserved."))
		case !s.marks.RoleManaged(a.Rolename):
			p = cmp(p, problem.New(problem.UnknownRole, fmt.Sprintf("Role '%s' is not managed.", a.Rolename)))
		}
		out = append(out, dynsec.RoleAssignment{Rolename: a.Rolename, Priority: a.Priority})
	}
	return out, errs, p
}

func (s *server) checkGroupAssignments(in []groupAssignReq, pointer string) ([]dynsec.GroupAssignment, []rules.FieldError, *problem.Problem) {
	var (
		out  []dynsec.GroupAssignment
		errs []rules.FieldError
		p    *problem.Problem
		seen = map[string]bool{}
	)
	for i, a := range in {
		ptr := fmt.Sprintf("%s/%d", pointer, i)
		switch {
		case a.Groupname == "":
			errs = append(errs, field(ptr+"/groupname", "required", "Field 'groupname' is required."))
			continue
		case seen[a.Groupname]:
			errs = append(errs, field(ptr+"/groupname", "duplicate", fmt.Sprintf("Group '%s' is listed twice.", a.Groupname)))
			continue
		}
		seen[a.Groupname] = true
		if a.Priority != nil {
			if msg := rules.CheckPriority(*a.Priority); msg != "" {
				errs = append(errs, field(ptr+"/priority", "out_of_range", "Field 'priority' "+msg+"."))
				continue
			}
		}
		if !s.marks.GroupManaged(a.Groupname) {
			p = cmp(p, problem.New(problem.UnknownGroup, fmt.Sprintf("Group '%s' is not managed.", a.Groupname)))
		}
		out = append(out, dynsec.GroupAssignment{Groupname: a.Groupname, Priority: a.Priority})
	}
	return out, errs, p
}

// cmp returns the first non-nil problem; a 403 wins over a 422.
func cmp(a, b *problem.Problem) *problem.Problem {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.Code.Status() == http.StatusForbidden && a.Code.Status() != http.StatusForbidden:
		return b
	}
	return a
}

// --- small helpers ---

func (s *server) getClient(ctx context.Context, name string) (model.Client, error) {
	return execDecode(s, ctx, dynsec.GetClient{Username: name}, model.DecodeClient)
}

func (s *server) getClientErr(ctx context.Context, name string) error {
	_, err := s.getClient(ctx, name)
	return err
}

func (s *server) getGroup(ctx context.Context, name string) (model.Group, error) {
	return execDecode(s, ctx, dynsec.GetGroup{Groupname: name}, model.DecodeGroup)
}

func (s *server) getRole(ctx context.Context, name string) (model.Role, error) {
	return execDecode(s, ctx, dynsec.GetRole{Rolename: name}, model.DecodeRole)
}

func isNotFound(err error) bool {
	var ce *dynsec.CommandError
	return errors.As(err, &ce) && ce.NotFound()
}

func hasRole(roles []model.RoleRef, name string) bool {
	return slices.ContainsFunc(roles, func(r model.RoleRef) bool { return r.Rolename == name })
}

func sameRoles(got []model.RoleRef, want []dynsec.RoleAssignment) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !slices.Contains(got, model.RoleRef{Rolename: w.Rolename, Priority: prioOr(w.Priority, model.DefaultAssignmentPriority)}) {
			return false
		}
	}
	return true
}

func sameGroups(got []model.GroupRef, want []dynsec.GroupAssignment) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !slices.Contains(got, model.GroupRef{Groupname: w.Groupname, Priority: prioOr(w.Priority, model.DefaultAssignmentPriority)}) {
			return false
		}
	}
	return true
}

func prioOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// generatedOrEmpty: a password given by the caller is never returned
// (specification 4.3, S-12).
func generatedOrEmpty(password string, generated bool) string {
	if generated {
		return password
	}
	return ""
}

func toDynsecACLs(in []rules.ACL) []dynsec.ACL {
	out := make([]dynsec.ACL, 0, len(in))
	for _, a := range in {
		out = append(out, dynsec.ACL{ACLType: a.ACLType, Topic: a.Topic, Priority: a.Priority, Allow: a.Allow})
	}
	return out
}

func toModelACLs(in []rules.ACL) []model.ACL {
	out := make([]model.ACL, 0, len(in))
	for _, a := range in {
		out = append(out, model.ACL{ACLType: a.ACLType, Topic: a.Topic, Allow: a.Allow, Priority: a.Priority})
	}
	model.SortACLs(out)
	return out
}
