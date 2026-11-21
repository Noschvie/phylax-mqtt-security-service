// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"testing"
)

// Data as Mosquitto 2.0.18 / 2.1.2 answers (priority -1 and disabled false
// are left out).
const (
	getClientData = `{"client":{"username":"dev1","disabled":true,"roles":[{"rolename":"tf_role_x"},{"rolename":"role_security_manager","priority":3}],"groups":[{"groupname":"tf_group_x"}]}}`
	getGroupData  = `{"group":{"groupname":"tf_group_x","clients":[{"username":"zz"},{"username":"dev1"}],"roles":[{"rolename":"tf_role_x"}]}}`
	getRoleData   = `{"role":{"rolename":"tf_role_x","acls":[{"acltype":"subscribePattern","topic":"b/#","priority":5,"allow":false},{"acltype":"publishClientSend","topic":"a/#","priority":0,"allow":true},{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD","allow":false}]}}`
)

func TestDecodeClient(t *testing.T) {
	c, err := DecodeClient(json.RawMessage(getClientData))
	if err != nil {
		t.Fatal(err)
	}
	want := Client{
		Username: "dev1", AuthType: AuthPassword, Disabled: true,
		Roles:  []RoleRef{{"role_security_manager", 3}, {"tf_role_x", -1}},
		Groups: []GroupRef{{"tf_group_x", -1}},
		ETag:   c.ETag,
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v\nwant %+v", c, want)
	}
	if !regexp.MustCompile(`^"c-[0-9a-f]{16}"$`).MatchString(c.ETag) {
		t.Errorf("ETag %s", c.ETag)
	}
}

func TestAllFieldsPresent(t *testing.T) {
	c, _ := DecodeClient(json.RawMessage(`{"client":{"username":"CN=homeassistant,O=mqtt-apps"}}`))
	b, _ := json.Marshal(c)
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	want := `{"username":"CN=homeassistant,O=mqtt-apps","textname":"","textdescription":"","authType":"certificate","disabled":false,"roles":[],"groups":[],"etag":` + q(c.ETag) + `}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	g, _ := DecodeGroup(json.RawMessage(`{"group":{"groupname":"g"}}`))
	if b, _ := json.Marshal(g); string(b) != `{"groupname":"g","textname":"","roles":[],"clients":[],"etag":`+q(g.ETag)+`}` {
		t.Errorf("group %s", b)
	}
	r, _ := DecodeRole(json.RawMessage(`{"role":{"rolename":"r"}}`))
	if b, _ := json.Marshal(r); string(b) != `{"rolename":"r","textname":"","acls":[],"etag":`+q(r.ETag)+`}` {
		t.Errorf("role %s", b)
	}
}

func TestDecodeGroupAndRoleSorted(t *testing.T) {
	g, err := DecodeGroup(json.RawMessage(getGroupData))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Clients, []ClientRef{{"dev1"}, {"zz"}}) {
		t.Errorf("clients %v", g.Clients)
	}
	r, err := DecodeRole(json.RawMessage(getRoleData))
	if err != nil {
		t.Fatal(err)
	}
	want := []ACL{
		{"publishClientReceive", "stat/+/FILEDOWNLOAD", false, 0},
		{"publishClientSend", "a/#", true, 0},
		{"subscribePattern", "b/#", false, 5},
	}
	if !reflect.DeepEqual(r.ACLs, want) {
		t.Errorf("acls %v", r.ACLs)
	}
}

func TestSortByCodePoints(t *testing.T) {
	acls := []ACL{{"a", "stat/+/x", true, 0}, {"a", "stat/#", true, 0}}
	SortACLs(acls)
	if acls[0].Topic != "stat/#" {
		t.Errorf("%v: stat/# sorts before stat/+/", acls)
	}
	cs, _ := DecodeClients(json.RawMessage(`{"clients":[{"username":"wz-x"},{"username":"CN=a,O=b"},{"username":"Wz"}]}`))
	if cs[0].Username != "CN=a,O=b" || cs[1].Username != "Wz" || cs[2].Username != "wz-x" {
		t.Errorf("order %v", cs)
	}
}

func TestETagRules(t *testing.T) {
	base, _ := DecodeClient(json.RawMessage(`{"client":{"username":"u","roles":[{"rolename":"a"},{"rolename":"b"}]}}`))

	same := []string{
		// Order of roles from DynSec does not matter.
		`{"client":{"username":"u","roles":[{"rolename":"b"},{"rolename":"a"}]}}`,
		// Group membership belongs to the group (S-4).
		`{"client":{"username":"u","roles":[{"rolename":"a"},{"rolename":"b"}],"groups":[{"groupname":"g"}]}}`,
		// Explicit defaults equal left-out fields.
		`{"client":{"username":"u","disabled":false,"roles":[{"rolename":"a","priority":-1},{"rolename":"b"}]}}`,
	}
	for _, d := range same {
		c, _ := DecodeClient(json.RawMessage(d))
		if c.ETag != base.ETag {
			t.Errorf("ETag changed for %s", d)
		}
	}
	differs := []string{
		`{"client":{"username":"u","roles":[{"rolename":"a"}]}}`,
		`{"client":{"username":"u","roles":[{"rolename":"a","priority":1},{"rolename":"b"}]}}`,
		`{"client":{"username":"u","disabled":true,"roles":[{"rolename":"a"},{"rolename":"b"}]}}`,
		`{"client":{"username":"u","textname":"x","roles":[{"rolename":"a"},{"rolename":"b"}]}}`,
		`{"client":{"username":"v","roles":[{"rolename":"a"},{"rolename":"b"}]}}`,
	}
	for _, d := range differs {
		c, _ := DecodeClient(json.RawMessage(d))
		if c.ETag == base.ETag {
			t.Errorf("ETag unchanged for %s", d)
		}
	}

	g1, _ := DecodeGroup(json.RawMessage(`{"group":{"groupname":"g"}}`))
	g2, _ := DecodeGroup(json.RawMessage(`{"group":{"groupname":"g","clients":[{"username":"u"}]}}`))
	if g1.ETag == g2.ETag {
		t.Error("group ETag ignores clients")
	}
	r1, _ := DecodeRole(json.RawMessage(`{"role":{"rolename":"r","acls":[{"acltype":"a","topic":"t","allow":true}]}}`))
	r2, _ := DecodeRole(json.RawMessage(`{"role":{"rolename":"r","acls":[{"acltype":"a","topic":"t","allow":false}]}}`))
	if r1.ETag == r2.ETag {
		t.Error("role ETag ignores allow")
	}
	if r1.ETag[1] != 'r' || g1.ETag[1] != 'g' {
		t.Errorf("kinds %s %s", r1.ETag, g1.ETag)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, d := range []string{``, `null`, `{}`, `{"client":"x"}`, `not json`} {
		_, err := DecodeClient(json.RawMessage(d))
		var de *DecodeError
		if !errors.As(err, &de) || de.Command != "getClient" {
			t.Errorf("%q: error %v", d, err)
		}
	}
	if _, err := DecodeRoles(json.RawMessage(`{"totalCount":0}`)); err == nil {
		t.Error("listRoles without roles accepted")
	}
	if rs, err := DecodeRoles(json.RawMessage(`{"totalCount":0,"roles":[]}`)); err != nil || len(rs) != 0 {
		t.Errorf("empty list: %v %v", rs, err)
	}
}

func TestMarks(t *testing.T) {
	m := Marks{RolePrefix: "tf_", GroupPrefix: "tf_", ClientMarker: "managed-by: pmss"}
	if !m.ClientManaged(Client{Textdescription: "managed-by: pmss"}) || m.ClientManaged(Client{Textdescription: "managed-by: pmss "}) {
		t.Error("client marker must match exactly")
	}
	if !m.RoleManaged("tf_role_x") || m.RoleManaged("role_legacy") || !m.GroupManaged("tf_group") || m.GroupManaged("group") {
		t.Error("prefixes")
	}
}
