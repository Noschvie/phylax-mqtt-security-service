// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"strings"
	"testing"
)

func TestCheckUsername(t *testing.T) {
	ok := []string{"wz-steckdose-tv", "legacy_user", "CN=homeassistant,O=mqtt-apps", "Gerät-1"}
	bad := []string{"", "a b", "x=y", "a,b", "CN=", "tele/x", "a+b", "a#", "tab\tx", strings.Repeat("x", MaxNameBytes+1), "\xff"}
	for _, n := range ok {
		if msg := CheckUsername(n); msg != "" {
			t.Errorf("%q refused: %s", n, msg)
		}
	}
	for _, n := range bad {
		if CheckUsername(n) == "" {
			t.Errorf("%q accepted", n)
		}
	}
	if !IsReservedClient("pmss-admin-2") || IsReservedClient("xpmss-") {
		t.Error("reserved prefix")
	}
	if !IsCertificateClient("CN=a,O=b") || IsCertificateClient("cn=a") {
		t.Error("certificate client")
	}
}

func TestCheckObjectName(t *testing.T) {
	if CheckObjectName("tf_role_x", "tf_") != "" || CheckObjectName("tf_", "tf_") == "" ||
		CheckObjectName("role_legacy", "tf_") == "" || CheckObjectName("tf_a b", "tf_") == "" {
		t.Error("object names")
	}
}

func TestPassword(t *testing.T) {
	for range 100 {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if msg := CheckPassword(p); msg != "" {
			t.Fatalf("generated %q: %s", p, msg)
		}
	}
	a, _ := GeneratePassword()
	b, _ := GeneratePassword()
	if a == b {
		t.Error("two equal passwords")
	}
	for _, p := range []string{"", "short", "Q7mXr2Lk9pTz4WbN8cVd3Hs;", "Q7mXr2Lk9pTz4WbN8cVd3Hs ", "Q7mXr2Lk9pTz4WbN8cVd3HsFx", "Q7mXr2Lk9pTz4WbN8cVd3Hsä"} {
		msg := CheckPassword(p)
		if msg == "" {
			t.Errorf("%q accepted", p)
		}
		if p != "" && strings.Contains(msg, p) {
			t.Errorf("message contains the password")
		}
	}
}

func TestTopicFilter(t *testing.T) {
	for _, f := range []string{"#", "a/#", "+/b", "a/+/c", "$SYS/#", "cmnd/%u/#", "a//b"} {
		if msg := CheckTopicFilter(f); msg != "" {
			t.Errorf("%q: %s", f, msg)
		}
	}
	for _, f := range []string{"", "a#", "a/#/b", "a+/b", "a/b+", "x\x00"} {
		if CheckTopicFilter(f) == "" {
			t.Errorf("%q accepted", f)
		}
	}
}

func TestFiltersOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"stat/#", "stat/+/FILEDOWNLOAD", true},
		{"stat/+/FILEDOWNLOAD", "stat/x/FILEDOWNLOAD", true},
		{"stat/#", "tele/#", false},
		{"a/b", "a/b", true},
		{"a/b", "a/c", false},
		{"a/+", "a/b/c", false},
		{"#", "x/y", true},
		{"a/b", "a/b/c", false},
		{"a/#", "a", true},
	} {
		if got := FiltersOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("%q %q: %v", tc.a, tc.b, got)
		}
		if got := FiltersOverlap(tc.b, tc.a); got != tc.want {
			t.Errorf("%q %q (swapped): %v", tc.b, tc.a, got)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestCheckACLs(t *testing.T) {
	acls, errs := CheckACLs([]ACLInput{
		{ACLType: "subscribePattern", Topic: "stat/#", Allow: ptr(true)},
		{ACLType: "publishClientReceive", Topic: "stat/+/FILEDOWNLOAD", Allow: ptr(false), Priority: ptr(10)},
	}, "/acls")
	if len(errs) != 0 || len(acls) != 2 || acls[1].Priority != 10 || acls[0].Priority != 0 || acls[1].Allow {
		t.Fatalf("%+v %+v", acls, errs)
	}

	_, errs = CheckACLs([]ACLInput{
		{ACLType: "subscribePattern", Topic: "a/#", Allow: ptr(true)},
		{ACLType: "subscribePattern", Topic: "b"}, // allow missing
		{ACLType: "publish", Topic: "c", Allow: ptr(true)},
		{Topic: "d", Allow: ptr(true)},
		{ACLType: "publishClientSend", Topic: "a/#/x", Allow: ptr(true)},
		{ACLType: "publishClientSend", Topic: "e", Allow: ptr(true), Priority: ptr(100001)},
		{ACLType: "subscribePattern", Topic: "a/#", Allow: ptr(false)}, // duplicate of 0
	}, "/acls")
	want := map[string]string{
		"/acls/1/allow": "required", "/acls/2/acltype": "invalid_acltype", "/acls/3/acltype": "required",
		"/acls/4/topic": "invalid_topic", "/acls/5/priority": "out_of_range", "/acls/6": "duplicate_acl",
	}
	got := map[string]string{}
	for _, e := range errs {
		got[e.Pointer] = e.Code
	}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("%s: %q, want %q (all: %v)", p, got[p], c, got)
		}
	}
	if len(errs) != len(want) {
		t.Errorf("%d errors, want %d: %v", len(errs), len(want), errs)
	}
}

func TestDenyWarnings(t *testing.T) {
	acls := []ACL{
		{"publishClientReceive", "stat/#", true, 0},
		{"publishClientReceive", "stat/+/FILEDOWNLOAD", false, 0},   // same priority → warning
		{"publishClientReceive", "stat/+/FILEDOWNLOAD2", false, 10}, // higher → fine
		{"subscribePattern", "stat/+/FILEDOWNLOAD", false, 0},       // other type → fine
		{"publishClientReceive", "tele/x", false, 0},                // no overlap → fine
	}
	w := DenyWarnings(acls, "/acls")
	if len(w) != 1 || w[0].Pointer != "/acls/1" || w[0].Code != "deny_priority_not_higher" {
		t.Errorf("%+v", w)
	}
	if w := DenyWarnings(nil, "/acls"); w == nil || len(w) != 0 {
		t.Error("no warnings must be [] not null")
	}
}
