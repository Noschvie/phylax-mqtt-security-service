// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
)

// fakeBroker is an in-memory DynSec that answers like Mosquitto 2.0/2.1
// (messages and left-out defaults as observed). Faults can be injected:
// lose: the command is applied, but the answer is lost (ErrTimeout);
// refuse: the command is not sent (ErrUnavailable);
// dropACLType: createRole/modifyRole silently drop ACLs of this type.
type fakeBroker struct {
	mu      sync.Mutex
	clients map[string]*fbClient
	groups  map[string]*fbGroup
	roles   map[string]*fbRole
	order   []string // group membership in insertion order per group name

	lose        map[string]bool
	refuse      map[string]bool
	loseReads   bool // getX after a lost answer also times out
	dropACLType string
	calls       []string
}

type fbAssign struct {
	Name     string
	Priority *int
}

type fbClient struct {
	Username, Textname, Textdescription, Password string
	Disabled                                      bool
	Roles                                         []fbAssign
}

type fbGroup struct {
	Groupname, Textname string
	Roles               []fbAssign
	Clients             []string
	ClientPrio          map[string]*int
}

type fbRole struct {
	Rolename, Textname string
	ACLs               []dynsec.ACL
}

func newFakeBroker() *fakeBroker {
	return &fakeBroker{
		clients: map[string]*fbClient{}, groups: map[string]*fbGroup{}, roles: map[string]*fbRole{},
		lose: map[string]bool{}, refuse: map[string]bool{},
	}
}

func cmdErr(cmd dynsec.Command, msg string) error {
	return &dynsec.CommandError{Command: cmd.CommandName(), Message: msg}
}

func (f *fakeBroker) Execute(_ context.Context, cmd dynsec.Command) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := cmd.CommandName()
	f.calls = append(f.calls, name)
	if f.refuse[name] {
		return nil, fmt.Errorf("%w: %s not sent", dynsec.ErrUnavailable, name)
	}
	if f.loseReads && len(name) > 3 && name[:3] == "get" {
		return nil, fmt.Errorf("%w: %s", dynsec.ErrTimeout, name)
	}
	data, err := f.apply(cmd)
	if err == nil && f.lose[name] {
		return nil, fmt.Errorf("%w: %s", dynsec.ErrTimeout, name)
	}
	return data, err
}

func (f *fakeBroker) apply(cmd dynsec.Command) (json.RawMessage, error) {
	switch c := cmd.(type) {
	case dynsec.GetClient:
		cl, ok := f.clients[c.Username]
		if !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		return marshal(map[string]any{"client": f.clientJSON(cl)}), nil
	case dynsec.GetGroup:
		g, ok := f.groups[c.Groupname]
		if !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		return marshal(map[string]any{"group": groupJSON(g)}), nil
	case dynsec.GetRole:
		r, ok := f.roles[c.Rolename]
		if !ok {
			return nil, cmdErr(cmd, "Role not found")
		}
		return marshal(map[string]any{"role": roleJSON(r)}), nil
	case dynsec.ListClients:
		out := []any{}
		for _, cl := range f.clients {
			out = append(out, f.clientJSON(cl))
		}
		return marshal(map[string]any{"totalCount": len(out), "clients": out}), nil
	case dynsec.ListGroups:
		out := []any{}
		for _, g := range f.groups {
			out = append(out, groupJSON(g))
		}
		return marshal(map[string]any{"totalCount": len(out), "groups": out}), nil
	case dynsec.ListRoles:
		out := []any{}
		for _, r := range f.roles {
			out = append(out, roleJSON(r))
		}
		return marshal(map[string]any{"totalCount": len(out), "roles": out}), nil

	case dynsec.CreateClient:
		if _, ok := f.clients[c.Username]; ok {
			return nil, cmdErr(cmd, "Client already exists")
		}
		for _, r := range c.Roles {
			if _, ok := f.roles[r.Rolename]; !ok {
				return nil, cmdErr(cmd, "Role not found")
			}
		}
		for _, g := range c.Groups {
			if _, ok := f.groups[g.Groupname]; !ok {
				return nil, cmdErr(cmd, "Group not found")
			}
		}
		cl := &fbClient{Username: c.Username, Textname: c.Textname, Textdescription: c.Textdescription, Password: c.Password}
		for _, r := range c.Roles {
			cl.Roles = append(cl.Roles, fbAssign{r.Rolename, r.Priority})
		}
		f.clients[c.Username] = cl
		for _, g := range c.Groups {
			grp := f.groups[g.Groupname]
			grp.Clients = append(grp.Clients, c.Username)
			grp.ClientPrio[c.Username] = g.Priority
		}
	case dynsec.DeleteClient:
		if _, ok := f.clients[c.Username]; !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		delete(f.clients, c.Username)
		for _, g := range f.groups {
			g.Clients = slices.DeleteFunc(g.Clients, func(u string) bool { return u == c.Username })
		}
	case dynsec.SetClientPassword:
		cl, ok := f.clients[c.Username]
		if !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		cl.Password = c.Password
	case dynsec.AddClientRole:
		cl, ok := f.clients[c.Username]
		if !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		if _, ok := f.roles[c.Rolename]; !ok {
			return nil, cmdErr(cmd, "Role not found")
		}
		if slices.ContainsFunc(cl.Roles, func(a fbAssign) bool { return a.Name == c.Rolename }) {
			return nil, cmdErr(cmd, "Internal error") // as Mosquitto
		}
		cl.Roles = append(cl.Roles, fbAssign{c.Rolename, c.Priority})
	case dynsec.RemoveClientRole:
		cl, ok := f.clients[c.Username]
		if !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		n := len(cl.Roles)
		cl.Roles = slices.DeleteFunc(cl.Roles, func(a fbAssign) bool { return a.Name == c.Rolename })
		if len(cl.Roles) == n {
			return nil, cmdErr(cmd, "Role not found")
		}
	case dynsec.CreateGroup:
		if _, ok := f.groups[c.Groupname]; ok {
			return nil, cmdErr(cmd, "Group already exists")
		}
		f.groups[c.Groupname] = &fbGroup{Groupname: c.Groupname, Textname: c.Textname, ClientPrio: map[string]*int{}}
	case dynsec.DeleteGroup:
		if _, ok := f.groups[c.Groupname]; !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		delete(f.groups, c.Groupname)
	case dynsec.AddGroupClient:
		g, ok := f.groups[c.Groupname]
		if !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		if _, ok := f.clients[c.Username]; !ok {
			return nil, cmdErr(cmd, "Client not found")
		}
		if slices.Contains(g.Clients, c.Username) {
			return nil, cmdErr(cmd, "Client is already in this group")
		}
		g.Clients = append(g.Clients, c.Username)
	case dynsec.RemoveGroupClient:
		g, ok := f.groups[c.Groupname]
		if !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		if !slices.Contains(g.Clients, c.Username) {
			return nil, cmdErr(cmd, "Client not found")
		}
		g.Clients = slices.DeleteFunc(g.Clients, func(u string) bool { return u == c.Username })
	case dynsec.AddGroupRole:
		g, ok := f.groups[c.Groupname]
		if !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		if _, ok := f.roles[c.Rolename]; !ok {
			return nil, cmdErr(cmd, "Role not found")
		}
		if slices.ContainsFunc(g.Roles, func(a fbAssign) bool { return a.Name == c.Rolename }) {
			return nil, cmdErr(cmd, "Internal error")
		}
		g.Roles = append(g.Roles, fbAssign{c.Rolename, c.Priority})
	case dynsec.RemoveGroupRole:
		g, ok := f.groups[c.Groupname]
		if !ok {
			return nil, cmdErr(cmd, "Group not found")
		}
		g.Roles = slices.DeleteFunc(g.Roles, func(a fbAssign) bool { return a.Name == c.Rolename })
	case dynsec.CreateRole:
		if _, ok := f.roles[c.Rolename]; ok {
			return nil, cmdErr(cmd, "Role already exists")
		}
		f.roles[c.Rolename] = &fbRole{Rolename: c.Rolename, Textname: c.Textname, ACLs: f.filterACLs(c.ACLs)}
	case dynsec.DeleteRole:
		if _, ok := f.roles[c.Rolename]; !ok {
			return nil, cmdErr(cmd, "Role not found")
		}
		delete(f.roles, c.Rolename)
		for _, cl := range f.clients {
			cl.Roles = slices.DeleteFunc(cl.Roles, func(a fbAssign) bool { return a.Name == c.Rolename })
		}
		for _, g := range f.groups {
			g.Roles = slices.DeleteFunc(g.Roles, func(a fbAssign) bool { return a.Name == c.Rolename })
		}
	case dynsec.ModifyRole:
		r, ok := f.roles[c.Rolename]
		if !ok {
			return nil, cmdErr(cmd, "Role not found")
		}
		r.ACLs = f.filterACLs(c.ACLs)
	default:
		return nil, cmdErr(cmd, "Unknown command")
	}
	return nil, nil
}

func (f *fakeBroker) filterACLs(in []dynsec.ACL) []dynsec.ACL {
	return slices.DeleteFunc(slices.Clone(in), func(a dynsec.ACL) bool { return a.ACLType == f.dropACLType })
}

func assignJSON(key string, as []fbAssign) []any {
	out := []any{}
	for _, a := range as {
		m := map[string]any{key: a.Name}
		if a.Priority != nil && *a.Priority != -1 {
			m["priority"] = *a.Priority
		}
		out = append(out, m)
	}
	return out
}

func (f *fakeBroker) clientJSON(c *fbClient) map[string]any {
	m := map[string]any{"username": c.Username, "roles": assignJSON("rolename", c.Roles)}
	if c.Textname != "" {
		m["textname"] = c.Textname
	}
	if c.Textdescription != "" {
		m["textdescription"] = c.Textdescription
	}
	if c.Disabled {
		m["disabled"] = true
	}
	groups := []any{}
	for _, g := range f.groups {
		if slices.Contains(g.Clients, c.Username) {
			groups = append(groups, map[string]any{"groupname": g.Groupname})
		}
	}
	m["groups"] = groups
	return m
}

func groupJSON(g *fbGroup) map[string]any {
	clients := []any{}
	for _, c := range g.Clients {
		clients = append(clients, map[string]any{"username": c})
	}
	m := map[string]any{"groupname": g.Groupname, "roles": assignJSON("rolename", g.Roles), "clients": clients}
	if g.Textname != "" {
		m["textname"] = g.Textname
	}
	return m
}

func roleJSON(r *fbRole) map[string]any {
	m := map[string]any{"rolename": r.Rolename, "acls": r.ACLs}
	if r.Textname != "" {
		m["textname"] = r.Textname
	}
	return m
}

func marshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// sent reports whether a command with this name was executed.
func (f *fakeBroker) sent(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, name)
}
