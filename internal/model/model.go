// SPDX-License-Identifier: AGPL-3.0-or-later

// Package model turns DynSec data into the objects of the REST API:
// defaults filled in, lists sorted, ETag computed, managed flag and
// authType derived (specification 3.2, 4.2; design 6.4, 7.3).
//
// DynSec field names are kept (textname, rolename, acltype …); fields of
// the service are camelCase (S-8).
package model

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
)

// Defaults of DynSec, filled in when the plugin leaves the field out.
const (
	DefaultAssignmentPriority = -1
	DefaultACLPriority        = 0
)

// RoleRef is a role assigned to a client or group.
type RoleRef struct {
	Rolename string `json:"rolename"`
	Priority int    `json:"priority"`
}

// GroupRef is a group of a client.
type GroupRef struct {
	Groupname string `json:"groupname"`
	Priority  int    `json:"priority"`
}

// ClientRef is a client of a group (only the name, specification 4.2).
type ClientRef struct {
	Username string `json:"username"`
}

// ACL is one access rule of a role.
type ACL struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Allow    bool   `json:"allow"`
	Priority int    `json:"priority"`
}

// Client as in the export. All fields are always present.
type Client struct {
	Username        string     `json:"username"`
	Textname        string     `json:"textname"`
	Textdescription string     `json:"textdescription"`
	AuthType        string     `json:"authType"`
	Disabled        bool       `json:"disabled"`
	Roles           []RoleRef  `json:"roles"`
	Groups          []GroupRef `json:"groups"`
	ETag            string     `json:"etag"`
}

// Group as in the export.
type Group struct {
	Groupname string      `json:"groupname"`
	Textname  string      `json:"textname"`
	Roles     []RoleRef   `json:"roles"`
	Clients   []ClientRef `json:"clients"`
	ETag      string      `json:"etag"`
}

// Role as in the export.
type Role struct {
	Rolename string `json:"rolename"`
	Textname string `json:"textname"`
	ACLs     []ACL  `json:"acls"`
	ETag     string `json:"etag"`
}

// Auth types of clients.
const (
	AuthPassword    = "password"
	AuthCertificate = "certificate"
)

// AuthType derives the login of a client from its name: certificate
// clients at the app listener are named after the subject, CN=… (design
// 5.4).
func AuthType(username string) string {
	if strings.HasPrefix(username, "CN=") {
		return AuthCertificate
	}
	return AuthPassword
}

// Marks decides which objects are managed.
type Marks config.Managed

// ClientManaged: textdescription is exactly the marker.
func (m Marks) ClientManaged(c Client) bool { return c.Textdescription == m.ClientMarker }

// RoleManaged: the name starts with the role prefix.
func (m Marks) RoleManaged(name string) bool { return strings.HasPrefix(name, m.RolePrefix) }

// GroupManaged: the name starts with the group prefix.
func (m Marks) GroupManaged(name string) bool { return strings.HasPrefix(name, m.GroupPrefix) }

// --- decoding DynSec data ---

type dsRoleRef struct {
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority"`
}

type dsGroupRef struct {
	Groupname string `json:"groupname"`
	Priority  *int   `json:"priority"`
}

type dsClient struct {
	Username        string       `json:"username"`
	Textname        string       `json:"textname"`
	Textdescription string       `json:"textdescription"`
	Disabled        bool         `json:"disabled"` // only present when true
	Roles           []dsRoleRef  `json:"roles"`
	Groups          []dsGroupRef `json:"groups"`
}

type dsGroup struct {
	Groupname string      `json:"groupname"`
	Textname  string      `json:"textname"`
	Roles     []dsRoleRef `json:"roles"`
	Clients   []ClientRef `json:"clients"`
}

type dsACL struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Allow    bool   `json:"allow"`
	Priority *int   `json:"priority"`
}

type dsRole struct {
	Rolename string  `json:"rolename"`
	Textname string  `json:"textname"`
	ACLs     []dsACL `json:"acls"`
}

func prio(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func (d dsClient) normalize() Client {
	c := Client{
		Username:        d.Username,
		Textname:        d.Textname,
		Textdescription: d.Textdescription,
		AuthType:        AuthType(d.Username),
		Disabled:        d.Disabled,
		Roles:           roleRefs(d.Roles),
		Groups:          make([]GroupRef, 0, len(d.Groups)),
	}
	for _, g := range d.Groups {
		c.Groups = append(c.Groups, GroupRef{Groupname: g.Groupname, Priority: prio(g.Priority, DefaultAssignmentPriority)})
	}
	slices.SortFunc(c.Groups, func(a, b GroupRef) int { return cmp.Compare(a.Groupname, b.Groupname) })
	c.ETag = clientETag(c)
	return c
}

func (d dsGroup) normalize() Group {
	g := Group{Groupname: d.Groupname, Textname: d.Textname, Roles: roleRefs(d.Roles), Clients: slices.Clone(d.Clients)}
	if g.Clients == nil {
		g.Clients = []ClientRef{}
	}
	slices.SortFunc(g.Clients, func(a, b ClientRef) int { return cmp.Compare(a.Username, b.Username) })
	g.ETag = groupETag(g)
	return g
}

func (d dsRole) normalize() Role {
	r := Role{Rolename: d.Rolename, Textname: d.Textname, ACLs: make([]ACL, 0, len(d.ACLs))}
	for _, a := range d.ACLs {
		r.ACLs = append(r.ACLs, ACL{ACLType: a.ACLType, Topic: a.Topic, Allow: a.Allow, Priority: prio(a.Priority, DefaultACLPriority)})
	}
	SortACLs(r.ACLs)
	r.ETag = roleETag(r)
	return r
}

func roleRefs(in []dsRoleRef) []RoleRef {
	out := make([]RoleRef, 0, len(in))
	for _, r := range in {
		out = append(out, RoleRef{Rolename: r.Rolename, Priority: prio(r.Priority, DefaultAssignmentPriority)})
	}
	slices.SortFunc(out, func(a, b RoleRef) int { return cmp.Compare(a.Rolename, b.Rolename) })
	return out
}

// SortACLs sorts by acltype, then topic (Unicode code points, S-3).
func SortACLs(acls []ACL) {
	slices.SortFunc(acls, func(a, b ACL) int {
		return cmp.Or(cmp.Compare(a.ACLType, b.ACLType), cmp.Compare(a.Topic, b.Topic))
	})
}

// DecodeClient reads the data of getClient.
func DecodeClient(data json.RawMessage) (Client, error) {
	var d struct {
		Client *dsClient `json:"client"`
	}
	if err := decode(data, &d); err != nil || d.Client == nil {
		return Client{}, decodeError("getClient", err)
	}
	return d.Client.normalize(), nil
}

// DecodeGroup reads the data of getGroup.
func DecodeGroup(data json.RawMessage) (Group, error) {
	var d struct {
		Group *dsGroup `json:"group"`
	}
	if err := decode(data, &d); err != nil || d.Group == nil {
		return Group{}, decodeError("getGroup", err)
	}
	return d.Group.normalize(), nil
}

// DecodeRole reads the data of getRole.
func DecodeRole(data json.RawMessage) (Role, error) {
	var d struct {
		Role *dsRole `json:"role"`
	}
	if err := decode(data, &d); err != nil || d.Role == nil {
		return Role{}, decodeError("getRole", err)
	}
	return d.Role.normalize(), nil
}

// DecodeClients reads the data of listClients with verbose, sorted by name.
func DecodeClients(data json.RawMessage) ([]Client, error) {
	var d struct {
		Clients *[]dsClient `json:"clients"`
	}
	if err := decode(data, &d); err != nil || d.Clients == nil {
		return nil, decodeError("listClients", err)
	}
	out := make([]Client, 0, len(*d.Clients))
	for _, c := range *d.Clients {
		out = append(out, c.normalize())
	}
	slices.SortFunc(out, func(a, b Client) int { return cmp.Compare(a.Username, b.Username) })
	return out, nil
}

// DecodeGroups reads the data of listGroups with verbose, sorted by name.
func DecodeGroups(data json.RawMessage) ([]Group, error) {
	var d struct {
		Groups *[]dsGroup `json:"groups"`
	}
	if err := decode(data, &d); err != nil || d.Groups == nil {
		return nil, decodeError("listGroups", err)
	}
	out := make([]Group, 0, len(*d.Groups))
	for _, g := range *d.Groups {
		out = append(out, g.normalize())
	}
	slices.SortFunc(out, func(a, b Group) int { return cmp.Compare(a.Groupname, b.Groupname) })
	return out, nil
}

// DecodeRoles reads the data of listRoles with verbose, sorted by name.
func DecodeRoles(data json.RawMessage) ([]Role, error) {
	var d struct {
		Roles *[]dsRole `json:"roles"`
	}
	if err := decode(data, &d); err != nil || d.Roles == nil {
		return nil, decodeError("listRoles", err)
	}
	out := make([]Role, 0, len(*d.Roles))
	for _, r := range *d.Roles {
		out = append(out, r.normalize())
	}
	slices.SortFunc(out, func(a, b Role) int { return cmp.Compare(a.Rolename, b.Rolename) })
	return out, nil
}

func decode(data json.RawMessage, v any) error {
	if len(data) == 0 {
		return errEmpty
	}
	return json.Unmarshal(data, v)
}

// DecodeError: the plugin answered with data this service does not
// understand.
type DecodeError struct {
	Command string
	Err     error
}

func (e *DecodeError) Error() string {
	if e.Err != nil {
		return "unexpected " + e.Command + " data: " + e.Err.Error()
	}
	return "unexpected " + e.Command + " data"
}

func (e *DecodeError) Unwrap() error { return e.Err }

func decodeError(cmd string, err error) error { return &DecodeError{Command: cmd, Err: err} }

type emptyError struct{}

func (emptyError) Error() string { return "no data" }

var errEmpty = emptyError{}

// --- ETag (specification 3.2, S-4, S-5) ---
//
// A hash over the fields the object owns. Group membership belongs to the
// group, so it is not part of the client ETag; the password hash is never
// part of it. Lists are sorted, so the order in which DynSec answers does
// not matter.

func clientETag(c Client) string {
	return etag("c", struct {
		Username        string    `json:"username"`
		Textname        string    `json:"textname"`
		Textdescription string    `json:"textdescription"`
		Disabled        bool      `json:"disabled"`
		Roles           []RoleRef `json:"roles"`
	}{c.Username, c.Textname, c.Textdescription, c.Disabled, c.Roles})
}

func groupETag(g Group) string {
	return etag("g", struct {
		Groupname string      `json:"groupname"`
		Textname  string      `json:"textname"`
		Roles     []RoleRef   `json:"roles"`
		Clients   []ClientRef `json:"clients"`
	}{g.Groupname, g.Textname, g.Roles, g.Clients})
}

func roleETag(r Role) string {
	return etag("r", struct {
		Rolename string `json:"rolename"`
		Textname string `json:"textname"`
		ACLs     []ACL  `json:"acls"`
	}{r.Rolename, r.Textname, r.ACLs})
}

// etag returns a strong entity tag, e.g. "c-3f9a…" (16 hex digits of
// SHA-256 over the canonical JSON of the owned fields).
func etag(kind string, owned any) string {
	b, err := json.Marshal(owned)
	if err != nil {
		panic(err) // only strings, bools, ints and slices of them
	}
	sum := sha256.Sum256(b)
	return `"` + kind + "-" + hex.EncodeToString(sum[:8]) + `"`
}
