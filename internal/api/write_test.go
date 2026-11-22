// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/testrecord"
)

const marker = "managed-by: pmss"

type env struct {
	t    *testing.T
	fb   *fakeBroker
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fb := newFakeBroker()
	logs := &bytes.Buffer{}
	h := testrecord.Handler(NewHandler(Options{
		Logger:          slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Managed:         config.Default().Managed,
		MaxRequestBytes: config.MinRequestBytes,
		DynSec:          fb,
		Auth:            callerAuth{},
	}))
	// Base state: two managed roles, an unmanaged legacy user and role.
	fb.roles["tf_role_a"] = &fbRole{Rolename: "tf_role_a"}
	fb.roles["tf_role_b"] = &fbRole{Rolename: "tf_role_b"}
	fb.roles["role_legacy"] = &fbRole{Rolename: "role_legacy"}
	fb.roles["role_security_manager"] = &fbRole{Rolename: "role_security_manager"}
	fb.clients["legacy-shared-user"] = &fbClient{Username: "legacy-shared-user", Password: "old", Roles: []fbAssign{{Name: "role_legacy"}}}
	fb.clients["pmss-admin"] = &fbClient{Username: "pmss-admin", Roles: []fbAssign{{Name: "role_security_manager"}}}
	return &env{t: t, fb: fb, h: h, logs: logs}
}

// callerAuth grants everything and puts a caller into the context.
type callerAuth struct{}

func (callerAuth) Authorize(r *http.Request, _ auth.Scope) (*http.Request, *problem.Problem) {
	return r.WithContext(auth.WithCaller(r.Context(), auth.Caller{Subject: "sub-alice", Username: "alice", Azp: "tasmofleet"})), nil
}

func (e *env) do(method, path, body string, headers ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) etag(path string) string {
	e.t.Helper()
	rec := e.do(http.MethodGet, path, "")
	if rec.Code != 200 {
		e.t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	return rec.Header().Get("ETag")
}

func (e *env) status(rec *httptest.ResponseRecorder, want int, code problem.Code) map[string]any {
	e.t.Helper()
	if rec.Code != want {
		e.t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
	}
	var m map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			e.t.Fatalf("body: %v %s", err, rec.Body)
		}
	}
	if code != "" && m["code"] != string(code) {
		e.t.Fatalf("code %v, want %s: %s", m["code"], code, rec.Body)
	}
	return m
}

// auditRecords returns the audit records written so far.
func (e *env) auditRecords() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(e.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["log_type"] == "audit" {
			out = append(out, m)
		}
	}
	return out
}

func (e *env) lastAudit() map[string]any {
	e.t.Helper()
	recs := e.auditRecords()
	if len(recs) == 0 {
		e.t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

var password24 = regexp.MustCompile(`^[A-Za-z0-9]{24}$`)

func TestCreateClientGeneratedPassword(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodPost, "/api/v1/clients", `{"username":"wz-steckdose-tv","textname":"Wohnzimmer","roles":[{"rolename":"tf_role_a"}]}`)
	b := e.status(rec, 201, "")
	if rec.Header().Get("Location") != "/api/v1/clients/wz-steckdose-tv" || rec.Header().Get("ETag") == "" ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", rec.Header())
	}
	pw, _ := b["password"].(string)
	if !password24.MatchString(pw) || b["passwordGenerated"] != true {
		t.Errorf("password %q generated %v", pw, b["passwordGenerated"])
	}
	client := b["client"].(map[string]any)
	if client["textdescription"] != marker || client["managed"] != true || client["etag"] != rec.Header().Get("ETag") {
		t.Errorf("client %v", client)
	}
	if e.fb.clients["wz-steckdose-tv"].Password != pw {
		t.Error("broker has another password")
	}
	a := e.lastAudit()
	if a["action"] != "createClient" || a["result"] != "success" || a["after"] == nil {
		t.Errorf("audit %v", a)
	}
	if caller, _ := a["caller"].(map[string]any); caller["username"] != "alice" {
		t.Errorf("audit caller %v", a["caller"])
	}
	if strings.Contains(e.logs.String(), pw) {
		t.Error("password in the log")
	}
}

func TestCreateClientVariants(t *testing.T) {
	e := newEnv(t)
	given := "Q7mXr2Lk9pTz4WbN8cVd3HsF"
	b := e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev-2","password":"`+given+`"}`), 201, "")
	if _, ok := b["password"]; ok || b["passwordGenerated"] != false {
		t.Errorf("given password returned: %v", b)
	}
	if e.fb.clients["dev-2"].Password != given {
		t.Error("given password not set")
	}

	rec := e.do(http.MethodPost, "/api/v1/clients", `{"username":"CN=homeassistant,O=mqtt-apps"}`)
	b = e.status(rec, 201, "")
	if _, ok := b["password"]; ok || e.fb.clients["CN=homeassistant,O=mqtt-apps"].Password != "" {
		t.Error("certificate client got a password")
	}
	if rec.Header().Get("Location") != "/api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps" {
		t.Errorf("Location %q", rec.Header().Get("Location"))
	}

	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev-2"}`), 409, problem.AlreadyExists)
	if strings.Contains(e.logs.String(), given) {
		t.Error("password in the log")
	}
}

func TestCreateClientRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		body    string
		status  int
		code    problem.Code
		pointer string
	}{
		"reserved":              {`{"username":"pmss-admin-2"}`, 403, problem.ReservedName, ""},
		"comma":                 {`{"username":"a,b","password":"Q7mXr2Lk9pTz4WbN8cVd3HsF"}`, 422, problem.ValidationFailed, "/username"},
		"cert with password":    {`{"username":"CN=x,O=mqtt-apps","password":"Q7mXr2Lk9pTz4WbN8cVd3HsF"}`, 422, problem.ValidationFailed, "/password"},
		"password with ;":       {`{"username":"d","password":"Q7mXr2Lk9pTz4WbN8cVd3Hs;"}`, 422, problem.ValidationFailed, "/password"},
		"password too short":    {`{"username":"d","password":"short"}`, 422, problem.ValidationFailed, "/password"},
		"textdescription":       {`{"username":"d","textdescription":"x"}`, 422, problem.ValidationFailed, "/textdescription"},
		"no username":           {`{}`, 422, problem.ValidationFailed, "/username"},
		"not json":              {`{"username":`, 422, problem.ValidationFailed, ""},
		"unmanaged role":        {`{"username":"d","roles":[{"rolename":"role_legacy"}]}`, 422, problem.UnknownRole, ""},
		"reserved role":         {`{"username":"d","roles":[{"rolename":"role_security_manager"}]}`, 403, problem.ReservedName, ""},
		"missing role":          {`{"username":"d","roles":[{"rolename":"tf_role_missing"}]}`, 422, problem.UnknownRole, ""},
		"missing group":         {`{"username":"d","groups":[{"groupname":"tf_group_missing"}]}`, 422, problem.UnknownGroup, ""},
		"unmanaged group":       {`{"username":"d","groups":[{"groupname":"other"}]}`, 422, problem.UnknownGroup, ""},
		"duplicate role":        {`{"username":"d","roles":[{"rolename":"tf_role_a"},{"rolename":"tf_role_a"}]}`, 422, problem.ValidationFailed, "/roles/1/rolename"},
		"priority out of range": {`{"username":"d","roles":[{"rolename":"tf_role_a","priority":100001}]}`, 422, problem.ValidationFailed, "/roles/0/priority"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			b := e.status(e.do(http.MethodPost, "/api/v1/clients", tc.body), tc.status, tc.code)
			if tc.pointer != "" {
				errs, _ := b["errors"].([]any)
				if len(errs) == 0 || errs[0].(map[string]any)["pointer"] != tc.pointer {
					t.Errorf("errors %v, want pointer %s", b["errors"], tc.pointer)
				}
			}
			if _, ok := e.fb.clients["d"]; ok {
				t.Error("client created")
			}
			if a := e.lastAudit(); a["result"] != "failed" || a["code"] != string(tc.code) {
				t.Errorf("audit %v", a)
			}
		})
	}
}

func TestCreateClientChecksBeforeSending(t *testing.T) {
	e := newEnv(t)
	e.do(http.MethodPost, "/api/v1/clients", `{"username":"a,b"}`)
	e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"tf_role_x","acls":[{"acltype":"publish","topic":"x","allow":true}]}`)
	if e.fb.sent("createClient") || e.fb.sent("createRole") {
		t.Errorf("command sent despite invalid input: %v", e.fb.calls)
	}
}

// S-13: the answer is lost, but the client exists → 201 with the password.
func TestCreateClientLostAnswer(t *testing.T) {
	e := newEnv(t)
	e.fb.lose["createClient"] = true
	b := e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev-lost","roles":[{"rolename":"tf_role_a"}]}`), 201, "")
	if pw, _ := b["password"].(string); pw == "" || e.fb.clients["dev-lost"].Password != pw {
		t.Errorf("password %v", b["password"])
	}
}

func TestCreateClientNoAnswerUnknownState(t *testing.T) {
	e := newEnv(t)
	e.fb.lose["createClient"] = true
	e.fb.loseReads = true
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev-x"}`), 504, problem.BrokerTimeout)
	if a := e.lastAudit(); a["result"] != "unknown" {
		t.Errorf("audit %v", a)
	}
	if n := strings.Count(strings.Join(e.fb.calls, ","), "createClient"); n != 1 {
		t.Errorf("createClient sent %d times", n)
	}
}

func TestBrokerUnavailableNothingSent(t *testing.T) {
	e := newEnv(t)
	e.fb.refuse["createClient"] = true
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev-y"}`), 503, problem.BrokerUnavailable)
	if _, ok := e.fb.clients["dev-y"]; ok {
		t.Error("client created")
	}
}

func TestSetPassword(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev"}`), 201, "")
	path := "/api/v1/clients/dev/password"
	tag := e.etag("/api/v1/clients/dev")

	e.status(e.do(http.MethodPost, path, `{}`), 428, problem.PreconditionRequired)
	e.status(e.do(http.MethodPost, path, `{}`, "If-Match", `"c-0000000000000000"`), 412, problem.PreconditionFailed)

	rec := e.do(http.MethodPost, path, ``, "If-Match", tag) // empty body = generate
	b := e.status(rec, 200, "")
	if pw, _ := b["password"].(string); !password24.MatchString(pw) || e.fb.clients["dev"].Password != pw {
		t.Errorf("password %v", b["password"])
	}
	if rec.Header().Get("ETag") != tag || e.etag("/api/v1/clients/dev") != tag {
		t.Error("ETag changed by the password change (S-5)")
	}

	given := "h3RtY8vQm2NpXc6KzL4bWs9D"
	b = e.status(e.do(http.MethodPost, path, `{"password":"`+given+`"}`, "If-Match", tag), 200, "")
	if _, ok := b["password"]; ok || e.fb.clients["dev"].Password != given {
		t.Errorf("given password: %v", b)
	}
	e.status(e.do(http.MethodPost, path, `{"password":"x y"}`, "If-Match", tag), 422, problem.ValidationFailed)

	e.status(e.do(http.MethodPost, "/api/v1/clients/CN%3Dha%2CO%3Dmqtt-apps/password", `{}`, "If-Match", tag), 409, problem.CertificateClient)
	e.status(e.do(http.MethodPost, "/api/v1/clients/legacy-shared-user/password", `{}`, "If-Match", e.etag("/api/v1/clients/legacy-shared-user")), 403, problem.NotManaged)
	e.status(e.do(http.MethodPost, "/api/v1/clients/pmss-admin/password", `{}`, "If-Match", tag), 403, problem.ReservedName)
	e.status(e.do(http.MethodPost, "/api/v1/clients/missing/password", `{}`, "If-Match", tag), 404, problem.NotFound)

	// No answer: a password change cannot be read back → always 504.
	e.fb.lose["setClientPassword"] = true
	b = e.status(e.do(http.MethodPost, path, `{}`, "If-Match", tag), 504, problem.BrokerTimeout)
	if _, ok := b["password"]; ok {
		t.Error("password in a 504")
	}
	if strings.Contains(e.logs.String(), given) {
		t.Error("password in the log")
	}
}

func TestDeleteClient(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev"}`), 201, "")
	e.status(e.do(http.MethodDelete, "/api/v1/clients/dev", ""), 428, problem.PreconditionRequired)
	e.status(e.do(http.MethodDelete, "/api/v1/clients/dev", "", "If-Match", e.etag("/api/v1/clients/dev")), 204, "")
	e.status(e.do(http.MethodGet, "/api/v1/clients/dev", ""), 404, problem.NotFound)
	if a := e.lastAudit(); a["action"] != "deleteClient" || a["before"] == nil {
		t.Errorf("audit %v", a)
	}
	e.status(e.do(http.MethodDelete, "/api/v1/clients/legacy-shared-user", "", "If-Match", e.etag("/api/v1/clients/legacy-shared-user")), 403, problem.NotManaged)

	// Lost answer, client gone → 204.
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev2"}`), 201, "")
	e.fb.lose["deleteClient"] = true
	e.status(e.do(http.MethodDelete, "/api/v1/clients/dev2", "", "If-Match", e.etag("/api/v1/clients/dev2")), 204, "")
}

func TestClientRoles(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev","roles":[{"rolename":"tf_role_a"}]}`), 201, "")
	before := e.etag("/api/v1/clients/dev")

	rec := e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"tf_role_b"}`, "If-Match", before)
	b := e.status(rec, 200, "")
	added := rec.Header().Get("ETag")
	if added == before || b["etag"] != added || b["warnings"] == nil {
		t.Errorf("after add: %s %v", added, b)
	}
	// Same assignment again: nothing sent, same ETag.
	n := len(e.fb.calls)
	rec = e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"tf_role_b"}`, "If-Match", added)
	e.status(rec, 200, "")
	if rec.Header().Get("ETag") != added || strings.Contains(strings.Join(e.fb.calls[n:], ","), "addClientRole") {
		t.Error("repeated assignment changed something")
	}
	// Other priority: remove and add.
	rec = e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"tf_role_b","priority":5}`, "If-Match", added)
	if b := e.status(rec, 200, ""); !strings.Contains(rec.Body.String(), `{"rolename":"tf_role_b","priority":5}`) {
		t.Errorf("priority not changed: %v", b)
	}
	withPrio := rec.Header().Get("ETag")

	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"tf_role_b"}`, "If-Match", before), 412, problem.PreconditionFailed)
	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"role_legacy"}`, "If-Match", withPrio), 422, problem.UnknownRole)
	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"role_security_manager"}`, "If-Match", withPrio), 403, problem.ReservedName)
	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/roles", `{"rolename":"tf_role_missing"}`, "If-Match", withPrio), 422, problem.UnknownRole)

	rec = e.do(http.MethodDelete, "/api/v1/clients/dev/roles/tf_role_b", "", "If-Match", withPrio)
	e.status(rec, 204, "")
	if rec.Header().Get("ETag") != before {
		t.Error("ETag not restored after removing the role")
	}
	e.status(e.do(http.MethodDelete, "/api/v1/clients/dev/roles/tf_role_b", "", "If-Match", before), 404, problem.NotFound)
}

func TestGroups(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/groups", `{"groupname":"group_x"}`), 422, problem.ValidationFailed)
	rec := e.do(http.MethodPost, "/api/v1/groups", `{"groupname":"tf_group_tasmota","textname":"Tasmota"}`)
	e.status(rec, 201, "")
	if rec.Header().Get("Location") != "/api/v1/groups/tf_group_tasmota" {
		t.Errorf("Location %q", rec.Header().Get("Location"))
	}
	e.status(e.do(http.MethodPost, "/api/v1/groups", `{"groupname":"tf_group_tasmota"}`), 409, problem.AlreadyExists)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev"}`), 201, "")

	gpath, cpath := "/api/v1/groups/tf_group_tasmota", "/api/v1/clients/dev"
	g0, c0 := e.etag(gpath), e.etag(cpath)
	rec = e.do(http.MethodPost, gpath+"/clients", `{"username":"dev"}`, "If-Match", g0)
	e.status(rec, 200, "")
	g1 := rec.Header().Get("ETag")
	if g1 == g0 || e.etag(cpath) != c0 {
		t.Error("S-4: only the group ETag may change")
	}
	e.status(e.do(http.MethodPost, gpath+"/clients", `{"username":"legacy-shared-user"}`, "If-Match", g1), 422, problem.ValidationFailed)
	e.status(e.do(http.MethodPost, gpath+"/clients", `{"username":"pmss-admin"}`, "If-Match", g1), 403, problem.ReservedName)
	e.status(e.do(http.MethodPost, gpath+"/clients", `{"username":"nobody"}`, "If-Match", g1), 422, problem.ValidationFailed)

	rec = e.do(http.MethodPost, gpath+"/roles", `{"rolename":"tf_role_a"}`, "If-Match", g1)
	e.status(rec, 200, "")
	g2 := rec.Header().Get("ETag")
	rec = e.do(http.MethodDelete, gpath+"/roles/tf_role_a", "", "If-Match", g2)
	e.status(rec, 204, "")
	if rec.Header().Get("ETag") != g1 {
		t.Error("group ETag not restored")
	}
	rec = e.do(http.MethodDelete, gpath+"/clients/dev", "", "If-Match", g1)
	e.status(rec, 204, "")
	if rec.Header().Get("ETag") != g0 {
		t.Error("group ETag not restored after removing the client")
	}
	e.status(e.do(http.MethodDelete, "/api/v1/groups/other", "", "If-Match", g0), 403, problem.NotManaged)
	e.status(e.do(http.MethodDelete, gpath, "", "If-Match", g0), 204, "")
	if _, ok := e.fb.groups["tf_group_tasmota"]; ok {
		t.Error("group not deleted")
	}
}

func TestRoles(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"tf_role_ha","textname":"Home Assistant","acls":[
		{"acltype":"subscribePattern","topic":"stat/#","allow":true},
		{"acltype":"publishClientReceive","topic":"stat/#","allow":true},
		{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD","allow":false}]}`)
	b := e.status(rec, 201, "")
	warnings, _ := b["warnings"].([]any)
	if len(warnings) != 1 || warnings[0].(map[string]any)["code"] != "deny_priority_not_higher" || warnings[0].(map[string]any)["pointer"] != "/acls/2" {
		t.Errorf("warnings %v", b["warnings"])
	}
	acls := b["acls"].([]any)
	if acls[0].(map[string]any)["topic"] != "stat/#" || acls[1].(map[string]any)["topic"] != "stat/+/FILEDOWNLOAD" {
		t.Errorf("acls not sorted: %v", acls)
	}
	tag := rec.Header().Get("ETag")

	// Replace the whole list.
	rec = e.do(http.MethodPut, "/api/v1/roles/tf_role_ha/acls", `{"acls":[
		{"acltype":"publishClientReceive","topic":"stat/#","allow":true},
		{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD","allow":false,"priority":10}]}`, "If-Match", tag)
	b = e.status(rec, 200, "")
	if w, _ := b["warnings"].([]any); w == nil || len(w) != 0 {
		t.Errorf("warnings %v", b["warnings"])
	}
	if len(e.fb.roles["tf_role_ha"].ACLs) != 2 || rec.Header().Get("ETag") == tag {
		t.Error("ACLs not replaced")
	}
	tag = rec.Header().Get("ETag")

	e.status(e.do(http.MethodPut, "/api/v1/roles/tf_role_ha/acls", `{}`, "If-Match", tag), 422, problem.ValidationFailed)
	e.status(e.do(http.MethodPut, "/api/v1/roles/tf_role_ha/acls", `{"acls":[{"acltype":"subscribePattern","topic":"x"}]}`, "If-Match", tag), 422, problem.ValidationFailed)
	e.status(e.do(http.MethodPut, "/api/v1/roles/role_legacy/acls", `{"acls":[]}`, "If-Match", tag), 403, problem.NotManaged)
	e.status(e.do(http.MethodPut, "/api/v1/roles/role_security_manager/acls", `{"acls":[]}`, "If-Match", tag), 403, problem.ReservedName)

	// SEC-30: the broker drops an entry silently → 500 readback_mismatch.
	e.fb.dropACLType = "subscribeLiteral"
	e.status(e.do(http.MethodPut, "/api/v1/roles/tf_role_ha/acls", `{"acls":[{"acltype":"subscribeLiteral","topic":"x","allow":true}]}`, "If-Match", tag), 500, problem.ReadbackMismatch)
	// S-6: same on create → role deleted again.
	b = e.status(e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"tf_role_y","acls":[{"acltype":"subscribeLiteral","topic":"x","allow":true}]}`), 500, problem.ReadbackMismatch)
	if b["compensated"] != true || b["roleExists"] != false {
		t.Errorf("compensation %v", b)
	}
	if _, ok := e.fb.roles["tf_role_y"]; ok {
		t.Error("role not deleted again")
	}
	e.fb.dropACLType = ""

	e.status(e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"tf_role_ha"}`), 409, problem.AlreadyExists)
	e.status(e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"role_x"}`), 422, problem.ValidationFailed)
	e.status(e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"role_security_manager"}`), 403, problem.ReservedName)

	e.status(e.do(http.MethodDelete, "/api/v1/roles/tf_role_ha", "", "If-Match", e.etag("/api/v1/roles/tf_role_ha")), 204, "")
	if _, ok := e.fb.roles["tf_role_ha"]; ok {
		t.Error("role not deleted")
	}
}

func TestWriteNeedsScopeWrite(t *testing.T) {
	h := NewHandler(Options{Logger: discard(), DynSec: newFakeBroker(), Auth: onlyScope(auth.ScopeRead)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(`{"username":"d"}`)))
	if rec.Code != 403 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `scope="write"`) {
		t.Errorf("%d %v", rec.Code, rec.Header())
	}
}

func TestBodyLimitOnWrite(t *testing.T) {
	e := newEnv(t)
	big := `{"username":"` + strings.Repeat("x", config.MinRequestBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(big))
	req.ContentLength = -1 // unknown length: cut while reading
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	e.status(rec, 413, problem.PayloadTooLarge)
}

// Changing commands carry no secrets in their log representation.
func TestCommandLogValues(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("x", "cmd", dynsec.CreateClient{Username: "u", Password: "secret-pass"}, "cmd2", dynsec.SetClientPassword{Username: "u", Password: "secret-pass"})
	if strings.Contains(buf.String(), "secret-pass") {
		t.Error("password in the log")
	}
}
