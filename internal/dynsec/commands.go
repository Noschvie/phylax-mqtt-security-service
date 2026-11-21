// SPDX-License-Identifier: AGPL-3.0-or-later

package dynsec

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
