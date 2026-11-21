// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/model"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

// Reading endpoints (specification 4.1, 4.2; design 7.3). Single objects
// and lists show every object with the flag "managed"; the export holds
// only managed objects.

// Password policy and reserved names (design 5.4, 7.3; SEC-23, SEC-28).
const (
	PasswordLength   = 24
	PasswordAlphabet = "A-Za-z0-9"
)

// ReservedNames as reported in GET /api/v1/info; * matches any characters.
var ReservedNames = []string{"pmss-*", "role_security_manager"}

type infoResponse struct {
	APIVersion     string       `json:"apiVersion"`
	Implementation nameVersion  `json:"implementation"`
	Broker         brokerInfo   `json:"broker"`
	Managed        managedInfo  `json:"managed"`
	PasswordPolicy passwordInfo `json:"passwordPolicy"`
	ReservedNames  []string     `json:"reservedNames"`
	Limits         limitsInfo   `json:"limits"`
}

type nameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type brokerInfo struct {
	Product string `json:"product"`
	Version string `json:"version"`
}

type managedInfo struct {
	RolePrefix   string `json:"rolePrefix"`
	GroupPrefix  string `json:"groupPrefix"`
	ClientMarker string `json:"clientMarker"`
}

type passwordInfo struct {
	Length   int    `json:"length"`
	Alphabet string `json:"alphabet"`
}

type limitsInfo struct {
	MaxRequestBytes int64 `json:"maxRequestBytes"`
}

// handleInfo answers from the configuration; it needs no broker (S-2).
func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	m := s.opts.Managed
	writeJSON(w, http.StatusOK, infoResponse{
		APIVersion:     APIVersion,
		Implementation: nameVersion{Name: ImplementationName, Version: s.opts.Version},
		Broker:         brokerInfo{Product: "mosquitto", Version: s.opts.BrokerVersion()},
		Managed:        managedInfo{RolePrefix: m.RolePrefix, GroupPrefix: m.GroupPrefix, ClientMarker: m.ClientMarker},
		PasswordPolicy: passwordInfo{Length: PasswordLength, Alphabet: PasswordAlphabet},
		ReservedNames:  ReservedNames,
		Limits:         limitsInfo{MaxRequestBytes: s.opts.MaxRequestBytes},
	})
}

type exportResponse struct {
	ExportedAt string         `json:"exportedAt"`
	APIVersion string         `json:"apiVersion"`
	Clients    []model.Client `json:"clients"`
	Groups     []model.Group  `json:"groups"`
	Roles      []model.Role   `json:"roles"`
}

// handleExport returns all managed objects (specification 4.2, S-3). The
// three lists are read one after the other; DynSec has no snapshot, so a
// change in between can show up in one list only. The ETags let the caller
// detect that before changing anything.
func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	clients, groups, roles, ok := s.listAll(w, r)
	if !ok {
		return
	}
	out := exportResponse{
		ExportedAt: s.opts.Now().UTC().Format(time.RFC3339),
		APIVersion: APIVersion,
		Clients:    []model.Client{},
		Groups:     []model.Group{},
		Roles:      []model.Role{},
	}
	for _, c := range clients {
		if s.marks.ClientManaged(c) {
			out.Clients = append(out.Clients, c)
		}
	}
	for _, g := range groups {
		if s.marks.GroupManaged(g.Groupname) {
			out.Groups = append(out.Groups, g)
		}
	}
	for _, rl := range roles {
		if s.marks.RoleManaged(rl.Rolename) {
			out.Roles = append(out.Roles, rl)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) listAll(w http.ResponseWriter, r *http.Request) ([]model.Client, []model.Group, []model.Role, bool) {
	clients, err := execDecode(s, r.Context(), dynsec.ListClients{Verbose: true}, model.DecodeClients)
	if err != nil {
		s.brokerFailure(w, r, err)
		return nil, nil, nil, false
	}
	groups, err := execDecode(s, r.Context(), dynsec.ListGroups{Verbose: true}, model.DecodeGroups)
	if err != nil {
		s.brokerFailure(w, r, err)
		return nil, nil, nil, false
	}
	roles, err := execDecode(s, r.Context(), dynsec.ListRoles{Verbose: true}, model.DecodeRoles)
	if err != nil {
		s.brokerFailure(w, r, err)
		return nil, nil, nil, false
	}
	return clients, groups, roles, true
}

// Single objects and list entries carry "managed" in addition to the
// export fields.

type clientView struct {
	model.Client
	Managed bool `json:"managed"`
}

type groupView struct {
	model.Group
	Managed bool `json:"managed"`
}

type roleView struct {
	model.Role
	Managed bool `json:"managed"`
}

func (s *server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	c, err := execDecode(s, r.Context(), dynsec.GetClient{Username: name}, model.DecodeClient)
	if err != nil {
		s.objectFailure(w, r, err, "Client", name)
		return
	}
	w.Header().Set("ETag", c.ETag)
	writeJSON(w, http.StatusOK, clientView{c, s.marks.ClientManaged(c)})
}

func (s *server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("group")
	g, err := execDecode(s, r.Context(), dynsec.GetGroup{Groupname: name}, model.DecodeGroup)
	if err != nil {
		s.objectFailure(w, r, err, "Group", name)
		return
	}
	w.Header().Set("ETag", g.ETag)
	writeJSON(w, http.StatusOK, groupView{g, s.marks.GroupManaged(g.Groupname)})
}

func (s *server) handleGetRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("role")
	rl, err := execDecode(s, r.Context(), dynsec.GetRole{Rolename: name}, model.DecodeRole)
	if err != nil {
		s.objectFailure(w, r, err, "Role", name)
		return
	}
	w.Header().Set("ETag", rl.ETag)
	writeJSON(w, http.StatusOK, roleView{rl, s.marks.RoleManaged(rl.Rolename)})
}

// Lists (PMSS extra, not part of the specification).

func (s *server) handleListClients(w http.ResponseWriter, r *http.Request) {
	cs, err := execDecode(s, r.Context(), dynsec.ListClients{Verbose: true}, model.DecodeClients)
	if err != nil {
		s.brokerFailure(w, r, err)
		return
	}
	out := make([]clientView, 0, len(cs))
	for _, c := range cs {
		out = append(out, clientView{c, s.marks.ClientManaged(c)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := execDecode(s, r.Context(), dynsec.ListGroups{Verbose: true}, model.DecodeGroups)
	if err != nil {
		s.brokerFailure(w, r, err)
		return
	}
	out := make([]groupView, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupView{g, s.marks.GroupManaged(g.Groupname)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (s *server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	rs, err := execDecode(s, r.Context(), dynsec.ListRoles{Verbose: true}, model.DecodeRoles)
	if err != nil {
		s.brokerFailure(w, r, err)
		return
	}
	out := make([]roleView, 0, len(rs))
	for _, rl := range rs {
		out = append(out, roleView{rl, s.marks.RoleManaged(rl.Rolename)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

// --- helpers ---

func execDecode[T any](s *server, ctx context.Context, cmd dynsec.Command, dec func(json.RawMessage) (T, error)) (T, error) {
	var zero T
	if s.opts.DynSec == nil {
		return zero, errNoDynSec
	}
	data, err := s.opts.DynSec.Execute(ctx, cmd)
	if err != nil {
		return zero, err
	}
	return dec(data)
}

var errNoDynSec = errors.New("no DynSec client configured")

// objectFailure maps "not found" of a single object to 404, everything
// else like brokerFailure.
func (s *server) objectFailure(w http.ResponseWriter, r *http.Request, err error, kind, name string) {
	var ce *dynsec.CommandError
	if errors.As(err, &ce) && ce.NotFound() {
		problem.Write(w, r, problem.New(problem.NotFound, fmt.Sprintf("%s '%s' does not exist.", kind, name)))
		return
	}
	s.brokerFailure(w, r, err)
}

// brokerFailure maps errors of the broker connection (specification 3.5,
// 3.7): not sent → 503, no answer → 504, anything else → 502.
func (s *server) brokerFailure(w http.ResponseWriter, r *http.Request, err error) {
	var (
		ce *dynsec.CommandError
		de *model.DecodeError
		p  *problem.Problem
	)
	switch {
	case errors.Is(err, dynsec.ErrUnavailable):
		p = problem.New(problem.BrokerUnavailable, "No connection to the broker; nothing was sent.")
	case errors.Is(err, dynsec.ErrTimeout), errors.Is(err, context.Canceled):
		p = problem.New(problem.BrokerTimeout, "The broker did not answer in time.")
	case errors.As(err, &ce):
		p = problem.New(problem.BrokerError, ce.Command+": "+ce.Message)
	case errors.As(err, &de):
		p = problem.New(problem.BrokerError, "Unexpected answer from the broker.")
	case errors.Is(err, errNoDynSec):
		p = problem.New(problem.BrokerUnavailable, "No broker connection configured.")
	default:
		p = problem.New(problem.BrokerError, "Broker request failed.")
	}
	s.opts.Logger.LogAttrs(r.Context(), slog.LevelWarn, "broker request failed",
		slog.String("path", r.URL.Path), slog.String("code", string(p.Code)), slog.String("error", err.Error()))
	problem.Write(w, r, p)
}

// writeJSON sends v; API responses are never cached (they show the state
// of access rights).
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		problem.Write(w, nil, problem.New(problem.InternalError, ""))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
