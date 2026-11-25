// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/testrecord"
)

// fakeDynSec answers commands from canned DynSec data.
type fakeDynSec struct {
	data map[string]string // command name (+ ":" + object name) → data
	err  error
	cmds []dynsec.Command
}

func (f *fakeDynSec) Execute(_ context.Context, cmd dynsec.Command) (json.RawMessage, error) {
	f.cmds = append(f.cmds, cmd)
	if f.err != nil {
		return nil, f.err
	}
	key := cmd.CommandName()
	switch c := cmd.(type) {
	case dynsec.GetClient:
		key += ":" + c.Username
	case dynsec.GetGroup:
		key += ":" + c.Groupname
	case dynsec.GetRole:
		key += ":" + c.Rolename
	}
	d, ok := f.data[key]
	if !ok {
		return nil, &dynsec.CommandError{Command: cmd.CommandName(), Message: "Object not found"}
	}
	return json.RawMessage(d), nil
}

// allowAll grants every scope; denyWrite grants only read.
type allowAll struct{}

func (allowAll) Authorize(r *http.Request, _ auth.Scope) (*http.Request, *problem.Problem) {
	return r, nil
}

type onlyScope auth.Scope

func (o onlyScope) Authorize(r *http.Request, s auth.Scope) (*http.Request, *problem.Problem) {
	if auth.Scope(o) != s {
		return nil, &problem.Problem{Code: problem.InsufficientScope, WWWAuthenticate: `Bearer error="insufficient_scope", scope="` + string(s) + `"`}
	}
	return r, nil
}

// Broker state as Mosquitto reports it: unsorted, defaults left out, with
// unmanaged objects (admins, legacy user and role).
var brokerState = map[string]string{
	"listClients": `{"totalCount":5,"clients":[
		{"username":"wz-steckdose-tv","textname":"Wohnzimmer Steckdose TV","textdescription":"managed-by: pmss","roles":[{"rolename":"tf_role_dev_a4cf12345678"}],"groups":[{"groupname":"tf_group_tasmota"}]},
		{"username":"pmss-admin","roles":[{"rolename":"role_security_manager"}],"groups":[]},
		{"username":"legacy-shared-user","roles":[{"rolename":"role_legacy"}]},
		{"username":"CN=homeassistant,O=mqtt-apps","textname":"Home Assistant","textdescription":"managed-by: pmss","roles":[{"rolename":"tf_role_homeassistant"}]},
		{"username":"other","textdescription":"managed-by: someone else"}]}`,
	"listGroups": `{"totalCount":2,"groups":[
		{"groupname":"tf_group_tasmota","textname":"Tasmota-Geräte","roles":[{"rolename":"tf_role_tasmota"}],"clients":[{"username":"wz-steckdose-tv"}]},
		{"groupname":"legacy","clients":[]}]}`,
	"listRoles": `{"totalCount":4,"roles":[
		{"rolename":"tf_role_tasmota","textname":"Tasmota-Grundprofil","acls":[{"acltype":"subscribePattern","topic":"cmnd/%u/#","priority":0,"allow":true},{"acltype":"publishClientSend","topic":"tele/%u/#","priority":0,"allow":true},{"acltype":"publishClientSend","topic":"stat/%u/#","priority":0,"allow":true},{"acltype":"publishClientReceive","topic":"cmnd/%u/#","priority":0,"allow":true}]},
		{"rolename":"role_legacy","acls":[{"acltype":"publishClientSend","topic":"#","priority":0,"allow":true}]},
		{"rolename":"tf_role_homeassistant","textname":"Home Assistant","acls":[{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD","priority":10,"allow":false},{"acltype":"publishClientReceive","topic":"stat/#","priority":0,"allow":true}]},
		{"rolename":"tf_role_dev_a4cf12345678","acls":[]}]}`,
	"getClient:CN=homeassistant,O=mqtt-apps": `{"client":{"username":"CN=homeassistant,O=mqtt-apps","textname":"Home Assistant","textdescription":"managed-by: pmss","roles":[{"rolename":"tf_role_homeassistant"}]}}`,
	"getClient:legacy-shared-user":           `{"client":{"username":"legacy-shared-user","roles":[{"rolename":"role_legacy"}]}}`,
	"getGroup:tf_group_tasmota":              `{"group":{"groupname":"tf_group_tasmota","roles":[{"rolename":"tf_role_tasmota"}],"clients":[{"username":"wz-steckdose-tv"}]}}`,
	"getRole:tf_role_homeassistant":          `{"role":{"rolename":"tf_role_homeassistant","acls":[{"acltype":"publishClientReceive","topic":"stat/#","priority":0,"allow":true}]}}`,
}

func newTestHandler(f *fakeDynSec, authorizer auth.Authorizer) http.Handler {
	return testrecord.Handler(NewHandler(Options{
		Logger:          discard(),
		Version:         "v0.0.0-test",
		Managed:         config.Default().Managed,
		MaxRequestBytes: config.MinRequestBytes,
		DynSec:          f,
		Auth:            authorizer,
		BrokerVersion:   func() string { return "2.1.2" },
		Now:             func() time.Time { return time.Date(2026, 11, 20, 22, 30, 12, 0, time.FixedZone("CET", 3600)) },
	}))
}

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, rec.Body)
	}
	return m
}

func checkProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code problem.Code) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status %d, want %d: %s", rec.Code, status, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type %q", ct)
	}
	b := jsonBody(t, rec)
	if b["code"] != string(code) || b["status"] != float64(status) {
		t.Errorf("problem %v, want %s/%d", b, code, status)
	}
	return b
}

func TestInfo(t *testing.T) {
	rec := do(t, newTestHandler(&fakeDynSec{}, allowAll{}), http.MethodGet, "/api/v1/info")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	want := `{"apiVersion":"1.1","implementation":{"name":"phylax-mqtt-security-service","version":"v0.0.0-test"},` +
		`"broker":{"product":"mosquitto","version":"2.1.2"},` +
		`"managed":{"rolePrefix":"tf_","groupPrefix":"tf_","clientMarker":"managed-by: pmss"},` +
		`"passwordPolicy":{"length":24,"alphabet":"A-Za-z0-9"},"reservedNames":["pmss-*","role_security_manager"],` +
		`"limits":{"maxRequestBytes":1048576}}` + "\n"
	if rec.Body.String() != want {
		t.Errorf("got  %s\nwant %s", rec.Body, want)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("no Cache-Control: no-store")
	}
}

func TestExport(t *testing.T) {
	f := &fakeDynSec{data: brokerState}
	h := newTestHandler(f, allowAll{})
	rec := do(t, h, http.MethodGet, "/api/v1/export")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got exportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ExportedAt != "2026-11-20T21:30:12Z" || got.APIVersion != "1.1" {
		t.Errorf("header fields %q %q", got.ExportedAt, got.APIVersion)
	}
	names := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	// Only managed objects, sorted by code points (CN=… before wz-…).
	if c := names(len(got.Clients), func(i int) string { return got.Clients[i].Username }); !reflect.DeepEqual(c, []string{"CN=homeassistant,O=mqtt-apps", "wz-steckdose-tv"}) {
		t.Errorf("clients %v", c)
	}
	if g := names(len(got.Groups), func(i int) string { return got.Groups[i].Groupname }); !reflect.DeepEqual(g, []string{"tf_group_tasmota"}) {
		t.Errorf("groups %v", g)
	}
	if r := names(len(got.Roles), func(i int) string { return got.Roles[i].Rolename }); !reflect.DeepEqual(r, []string{"tf_role_dev_a4cf12345678", "tf_role_homeassistant", "tf_role_tasmota"}) {
		t.Errorf("roles %v", r)
	}
	ha := got.Clients[0]
	if ha.AuthType != "certificate" || ha.Roles[0].Priority != -1 || len(ha.Groups) != 0 || ha.Groups == nil {
		t.Errorf("client %+v", ha)
	}
	acls := got.Roles[1].ACLs
	if acls[0].Topic != "stat/#" || acls[1].Topic != "stat/+/FILEDOWNLOAD" || acls[1].Priority != 10 {
		t.Errorf("acls not sorted: %+v", acls)
	}
	for _, c := range got.Clients {
		if c.ETag == "" {
			t.Errorf("client %s without etag", c.Username)
		}
	}
	if strings.Contains(rec.Body.String(), `"managed"`) {
		t.Error("export entries carry managed (not in the specification)")
	}

	// Two exports of the same state are byte-identical.
	again := do(t, h, http.MethodGet, "/api/v1/export")
	if again.Body.String() != rec.Body.String() {
		t.Error("two exports of the same state differ")
	}
	// Verbose lists are requested.
	for _, c := range f.cmds {
		switch c := c.(type) {
		case dynsec.ListClients:
			if !c.Verbose {
				t.Error("listClients without verbose")
			}
		case dynsec.ListRoles:
			if !c.Verbose {
				t.Error("listRoles without verbose")
			}
		}
	}
}

func TestGetSingleObjects(t *testing.T) {
	h := newTestHandler(&fakeDynSec{data: brokerState}, allowAll{})

	rec := do(t, h, http.MethodGet, "/api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	b := jsonBody(t, rec)
	if b["username"] != "CN=homeassistant,O=mqtt-apps" || b["managed"] != true || b["authType"] != "certificate" {
		t.Errorf("client %v", b)
	}
	if etag := rec.Header().Get("ETag"); etag == "" || etag != b["etag"] {
		t.Errorf("ETag header %q, body %v", etag, b["etag"])
	}

	rec = do(t, h, http.MethodGet, "/api/v1/clients/legacy-shared-user")
	if b := jsonBody(t, rec); rec.Code != 200 || b["managed"] != false {
		t.Errorf("unmanaged client: %d %v", rec.Code, b)
	}

	rec = do(t, h, http.MethodGet, "/api/v1/groups/tf_group_tasmota")
	if b := jsonBody(t, rec); rec.Code != 200 || b["managed"] != true || rec.Header().Get("ETag") == "" {
		t.Errorf("group: %d %v", rec.Code, b)
	}
	rec = do(t, h, http.MethodGet, "/api/v1/roles/tf_role_homeassistant")
	if b := jsonBody(t, rec); rec.Code != 200 || b["managed"] != true || !strings.HasPrefix(rec.Header().Get("ETag"), `"r-`) {
		t.Errorf("role: %d %v", rec.Code, b)
	}

	for _, p := range []string{"/api/v1/clients/missing", "/api/v1/groups/missing", "/api/v1/roles/missing"} {
		b := checkProblem(t, do(t, h, http.MethodGet, p), 404, problem.NotFound)
		if b["instance"] != p {
			t.Errorf("instance %v", b["instance"])
		}
	}
}

func TestLists(t *testing.T) {
	h := newTestHandler(&fakeDynSec{data: brokerState}, allowAll{})
	rec := do(t, h, http.MethodGet, "/api/v1/clients")
	var got struct {
		Clients []clientView `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Clients) != 5 {
		t.Fatalf("clients %d %v: %s", len(got.Clients), err, rec.Body)
	}
	managed := map[string]bool{}
	for _, c := range got.Clients {
		managed[c.Username] = c.Managed
	}
	if !managed["wz-steckdose-tv"] || managed["pmss-admin"] || managed["legacy-shared-user"] || managed["other"] {
		t.Errorf("managed flags %v", managed)
	}
	for _, p := range []string{"/api/v1/groups", "/api/v1/roles"} {
		if rec := do(t, h, http.MethodGet, p); rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestBrokerErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   problem.Code
	}{
		{fmt.Errorf("%w: x", dynsec.ErrUnavailable), 503, problem.BrokerUnavailable},
		{fmt.Errorf("%w: x", dynsec.ErrTimeout), 504, problem.BrokerTimeout},
		{&dynsec.CommandError{Command: "listClients", Message: "Internal error"}, 502, problem.BrokerError},
		{fmt.Errorf("something"), 502, problem.BrokerError},
	} {
		h := newTestHandler(&fakeDynSec{err: tc.err}, allowAll{})
		for _, p := range []string{"/api/v1/export", "/api/v1/clients/x", "/api/v1/roles"} {
			checkProblem(t, do(t, h, http.MethodGet, p), tc.status, tc.code)
		}
	}
	// Data the service does not understand.
	h := newTestHandler(&fakeDynSec{data: map[string]string{"listClients": `{"clients":"x"}`}}, allowAll{})
	checkProblem(t, do(t, h, http.MethodGet, "/api/v1/export"), 502, problem.BrokerError)
}

func TestAuthorization(t *testing.T) {
	// Default: closed until the token check is configured.
	h := NewHandler(Options{Logger: discard(), DynSec: &fakeDynSec{data: brokerState}})
	for _, p := range []string{"/api/v1/info", "/api/v1/export", "/api/v1/clients/x"} {
		rec := do(t, h, http.MethodGet, p)
		checkProblem(t, rec, 401, problem.InvalidToken)
		if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
			t.Errorf("%s: WWW-Authenticate %q", p, rec.Header().Get("WWW-Authenticate"))
		}
	}
	// Health check needs no token.
	if rec := do(t, h, http.MethodGet, "/healthz"); rec.Code != 200 {
		t.Errorf("healthz %d", rec.Code)
	}

	// Reading needs scope read; write alone is not enough.
	h = newTestHandler(&fakeDynSec{data: brokerState}, onlyScope(auth.ScopeWrite))
	rec := do(t, h, http.MethodGet, "/api/v1/export")
	checkProblem(t, rec, 403, problem.InsufficientScope)
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `scope="read"`) {
		t.Errorf("WWW-Authenticate %q", rec.Header().Get("WWW-Authenticate"))
	}
	h = newTestHandler(&fakeDynSec{data: brokerState}, onlyScope(auth.ScopeRead))
	if rec := do(t, h, http.MethodGet, "/api/v1/export"); rec.Code != 200 {
		t.Errorf("read scope: %d", rec.Code)
	}
}

func TestUnknownRoutesAndBodyLimit(t *testing.T) {
	h := newTestHandler(&fakeDynSec{data: brokerState}, allowAll{})
	checkProblem(t, do(t, h, http.MethodGet, "/api/v1/nothing"), 404, problem.NotFound)
	rec := do(t, h, http.MethodPatch, "/api/v1/info")
	checkProblem(t, rec, 405, problem.MethodNotAllowed)
	if rec.Header().Get("Allow") != "GET" {
		t.Errorf("Allow %q", rec.Header().Get("Allow"))
	}

	big := httptest.NewRequest(http.MethodGet, "/api/v1/info", strings.NewReader(strings.Repeat("x", config.MinRequestBytes+1)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, big)
	checkProblem(t, rec, 413, problem.PayloadTooLarge)
}
