// SPDX-License-Identifier: AGPL-3.0-or-later

package dynsec

import "log/slog"

// Reading commands of the Control API. Field names as in the plugin's API
// reference; the changing commands follow with the write endpoints.

// ListClients lists clients; with Verbose the entries carry roles and
// groups. Count -1 means all.
type ListClients struct {
	Verbose bool `json:"verbose,omitempty"`
	Count   int  `json:"count,omitempty"`
	Offset  int  `json:"offset,omitempty"`
}

func (ListClients) CommandName() string { return "listClients" }

// GetClient reads one client. The response holds no password hash
// (tested, design 7.3).
type GetClient struct {
	Username string `json:"username"`
}

func (GetClient) CommandName() string { return "getClient" }

// ListGroups lists groups.
type ListGroups struct {
	Verbose bool `json:"verbose,omitempty"`
	Count   int  `json:"count,omitempty"`
	Offset  int  `json:"offset,omitempty"`
}

func (ListGroups) CommandName() string { return "listGroups" }

// GetGroup reads one group.
type GetGroup struct {
	Groupname string `json:"groupname"`
}

func (GetGroup) CommandName() string { return "getGroup" }

// ListRoles lists roles.
type ListRoles struct {
	Verbose bool `json:"verbose,omitempty"`
	Count   int  `json:"count,omitempty"`
	Offset  int  `json:"offset,omitempty"`
}

func (ListRoles) CommandName() string { return "listRoles" }

// GetRole reads one role with its ACLs.
type GetRole struct {
	Rolename string `json:"rolename"`
}

func (GetRole) CommandName() string { return "getRole" }

// Changing commands. Fields that DynSec defaults when left out (priority)
// are pointers, so "not given" and 0 stay apart; allow is always sent,
// because DynSec turns a missing allow into a deny rule (design 7.3).

// RoleAssignment of a client or group.
type RoleAssignment struct {
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority,omitempty"`
}

// GroupAssignment of a client.
type GroupAssignment struct {
	Groupname string `json:"groupname"`
	Priority  *int   `json:"priority,omitempty"`
}

// ACL of a role as sent to DynSec.
type ACL struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Priority int    `json:"priority"`
	Allow    bool   `json:"allow"`
}

// CreateClient creates a client with its roles and groups in one command.
// Mosquitto creates nothing if a role or group does not exist (tested with
// 2.0.18 and 2.1.2, see the integration tests).
type CreateClient struct {
	Username        string            `json:"username"`
	Password        string            `json:"password,omitempty"`
	Textname        string            `json:"textname,omitempty"`
	Textdescription string            `json:"textdescription,omitempty"`
	Roles           []RoleAssignment  `json:"roles,omitempty"`
	Groups          []GroupAssignment `json:"groups,omitempty"`
}

func (CreateClient) CommandName() string { return "createClient" }

// LogValue and String keep the password out of logs and error messages.
func (c CreateClient) LogValue() slog.Value { return slog.StringValue(c.String()) }
func (c CreateClient) String() string       { return "createClient " + c.Username }

type DeleteClient struct {
	Username string `json:"username"`
}

func (DeleteClient) CommandName() string { return "deleteClient" }

type SetClientPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (SetClientPassword) CommandName() string { return "setClientPassword" }

// LogValue and String keep the password out of logs and error messages.
func (c SetClientPassword) LogValue() slog.Value { return slog.StringValue(c.String()) }
func (c SetClientPassword) String() string       { return "setClientPassword " + c.Username }

type AddClientRole struct {
	Username string `json:"username"`
	Rolename string `json:"rolename"`
	Priority *int   `json:"priority,omitempty"`
}

func (AddClientRole) CommandName() string { return "addClientRole" }

type RemoveClientRole struct {
	Username string `json:"username"`
	Rolename string `json:"rolename"`
}

func (RemoveClientRole) CommandName() string { return "removeClientRole" }

type CreateGroup struct {
	Groupname string `json:"groupname"`
	Textname  string `json:"textname,omitempty"`
}

func (CreateGroup) CommandName() string { return "createGroup" }

type DeleteGroup struct {
	Groupname string `json:"groupname"`
}

func (DeleteGroup) CommandName() string { return "deleteGroup" }

type AddGroupClient struct {
	Groupname string `json:"groupname"`
	Username  string `json:"username"`
}

func (AddGroupClient) CommandName() string { return "addGroupClient" }

type RemoveGroupClient struct {
	Groupname string `json:"groupname"`
	Username  string `json:"username"`
}

func (RemoveGroupClient) CommandName() string { return "removeGroupClient" }

type AddGroupRole struct {
	Groupname string `json:"groupname"`
	Rolename  string `json:"rolename"`
	Priority  *int   `json:"priority,omitempty"`
}

func (AddGroupRole) CommandName() string { return "addGroupRole" }

type RemoveGroupRole struct {
	Groupname string `json:"groupname"`
	Rolename  string `json:"rolename"`
}

func (RemoveGroupRole) CommandName() string { return "removeGroupRole" }

// CreateRole creates a role with its full ACL list in one command (S-6).
type CreateRole struct {
	Rolename string `json:"rolename"`
	Textname string `json:"textname,omitempty"`
	ACLs     []ACL  `json:"acls"`
}

func (CreateRole) CommandName() string { return "createRole" }

type DeleteRole struct {
	Rolename string `json:"rolename"`
}

func (DeleteRole) CommandName() string { return "deleteRole" }

// ModifyRole with ACLs replaces the whole ACL list in one command (A-4).
// DynSec silently drops entries it does not understand, so the caller
// validates first and reads back afterwards (SEC-30).
type ModifyRole struct {
	Rolename string `json:"rolename"`
	ACLs     []ACL  `json:"acls"`
}

func (ModifyRole) CommandName() string { return "modifyRole" }

// ModifyClient with only textname leaves all other fields as they are
// (tested with Mosquitto 2.0.18).
type ModifyClient struct {
	Username string `json:"username"`
	Textname string `json:"textname"`
}

func (ModifyClient) CommandName() string { return "modifyClient" }

// EnableClient and DisableClient act on password logins only; DynSec does
// not check disabled for certificate logins (design 5.2).
type EnableClient struct {
	Username string `json:"username"`
}

func (EnableClient) CommandName() string { return "enableClient" }

type DisableClient struct {
	Username string `json:"username"`
}

func (DisableClient) CommandName() string { return "disableClient" }

// AddRoleACL adds one ACL; allow is always sent (a missing allow is a deny
// rule in DynSec).
type AddRoleACL struct {
	Rolename string `json:"rolename"`
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Priority int    `json:"priority"`
	Allow    bool   `json:"allow"`
}

func (AddRoleACL) CommandName() string { return "addRoleACL" }

type RemoveRoleACL struct {
	Rolename string `json:"rolename"`
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
}

func (RemoveRoleACL) CommandName() string { return "removeRoleACL" }
