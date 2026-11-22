// SPDX-License-Identifier: AGPL-3.0-or-later

// Package e2e tests the whole path of design 7.9: token from Keycloak →
// REST → MQTT/mTLS → DynSec, against the running service of
// test/integration/compose.yaml.
//
//	PMSS_TEST_E2E_URL=http://127.0.0.1:18080 \
//	PMSS_TEST_KEYCLOAK=http://127.0.0.1:8180 \
//	PMSS_TEST_BROKER_PLAIN=127.0.0.1:18883 \
//	PMSS_TEST_E2E_LOG=pmss.log \
//	  go test -race -count=1 -v ./test/integration/e2e/
//
// PMSS_TEST_E2E_LOG is optional: a file with the JSON log of the service.
// With it the test checks the audit records and that no password or
// token reaches the log.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
)

const (
	audience      = "phylax-mqtt-security-service"
	tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessType    = "urn:ietf:params:oauth:token-type:access_token"
)

type env struct {
	t      *testing.T
	api    string
	realm  string
	broker string
	// secrets that must never appear in the service log
	secrets []string
}

func setup(t *testing.T) *env {
	api, kc := os.Getenv("PMSS_TEST_E2E_URL"), os.Getenv("PMSS_TEST_KEYCLOAK")
	if api == "" || kc == "" {
		t.Skip("PMSS_TEST_E2E_URL and PMSS_TEST_KEYCLOAK not set (needs test/integration/compose.yaml)")
	}
	e := &env{t: t, api: strings.TrimRight(api, "/"), realm: strings.TrimRight(kc, "/") + "/realms/pmss-test", broker: os.Getenv("PMSS_TEST_BROKER_PLAIN")}
	// The service connects to the broker in the background.
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(e.api + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("service not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
	return e
}

// --- Keycloak -----------------------------------------------------------

type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func (e *env) token(client, secret string, form url.Values) tokens {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tr tokens
	_ = json.Unmarshal(body, &tr)
	if tr.AccessToken == "" {
		e.t.Fatalf("no token for %s: %d %s", client, resp.StatusCode, body)
	}
	e.secrets = append(e.secrets, tr.AccessToken, tr.IDToken, tr.RefreshToken)
	return tr
}

func (e *env) serviceAccount(client string) string {
	return e.token(client, client+"-secret", url.Values{"grant_type": {"client_credentials"}}).AccessToken
}

// user logs in at TasmoFleet (password grant of the test realm).
func (e *env) user(name string) tokens {
	return e.token("tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {"password"}, "username": {name}, "password": {name}, "scope": {"openid"},
	})
}

// exchange is what TasmoFleet does before it calls the service (T-2).
func (e *env) exchange(subject, scope string) string {
	return e.token("tasmofleet-test", "tasmofleet-test-secret", url.Values{
		"grant_type": {tokenExchange}, "subject_token": {subject}, "subject_token_type": {accessType},
		"requested_token_type": {accessType}, "audience": {audience}, "scope": {scope},
	}).AccessToken
}

// --- Service ------------------------------------------------------------

type result struct {
	status int
	header http.Header
	body   map[string]any
}

func (e *env) call(token, method, path, body string, headers ...string) result {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.api+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := result{status: resp.StatusCode, header: resp.Header}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

func (e *env) want(r result, status int, code string) result {
	e.t.Helper()
	if r.status != status || (code != "" && r.body["code"] != code) {
		e.t.Fatalf("got %d %v, want %d %s", r.status, r.body, status, code)
	}
	if status >= 400 && !strings.HasPrefix(r.header.Get("Content-Type"), "application/problem+json") {
		e.t.Errorf("Content-Type %q", r.header.Get("Content-Type"))
	}
	return r
}

func randomID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Tests --------------------------------------------------------------

func TestTokens(t *testing.T) {
	e := setup(t)

	// No token, broken header.
	r := e.want(e.call("", "GET", "/api/v1/info", ""), 401, "invalid_token")
	if !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate %q", r.header.Get("WWW-Authenticate"))
	}
	e.want(e.call("not-a-jwt", "GET", "/api/v1/info", ""), 401, "invalid_token")

	// msm-test-ro: read yes, write no.
	ro := e.serviceAccount("msm-test-ro")
	r = e.want(e.call(ro, "GET", "/api/v1/info", ""), 200, "")
	if r.body["apiVersion"] == nil || !strings.HasPrefix(r.body["apiVersion"].(string), "1.") {
		t.Errorf("info %v", r.body)
	}
	if lim := r.body["limits"].(map[string]any)["maxRequestBytes"].(float64); lim < 1<<20 {
		t.Errorf("maxRequestBytes %v", lim)
	}
	r = e.want(e.call(ro, "POST", "/api/v1/groups", `{"groupname":"tf_group_e2e_ro"}`), 403, "insufficient_scope")
	if !strings.Contains(r.header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("WWW-Authenticate %q", r.header.Get("WWW-Authenticate"))
	}

	// Service account with write in the client but without security-admin.
	e.want(e.call(e.serviceAccount("msm-test-rw-norole"), "POST", "/api/v1/groups", `{"groupname":"tf_group_e2e_norole"}`), 403, "insufficient_scope")

	// Tokens of TasmoFleet itself: aud without the service, ID and refresh token.
	alice := e.user("alice")
	e.want(e.call(alice.AccessToken, "GET", "/api/v1/info", ""), 401, "invalid_token")
	e.want(e.call(alice.IDToken, "GET", "/api/v1/info", ""), 401, "invalid_token")
	e.want(e.call(alice.RefreshToken, "GET", "/api/v1/info", ""), 401, "invalid_token")

	// Old path without version.
	e.want(e.call(ro, "GET", "/api/export", ""), 404, "")
	e.checkLog(nil)
}

// Token exchange (T-2): alice has security-admin, bob has not.
func TestTokenExchange(t *testing.T) {
	e := setup(t)
	group := "tf_group_e2e_" + randomID()

	aliceTok := e.exchange(e.user("alice").AccessToken, "read write")
	r := e.want(e.call(aliceTok, "POST", "/api/v1/groups", `{"groupname":"`+group+`"}`), 201, "")
	etag := r.header.Get("ETag")
	t.Cleanup(func() {
		r := e.call(aliceTok, "GET", "/api/v1/groups/"+group, "")
		if r.status == 200 {
			e.call(aliceTok, "DELETE", "/api/v1/groups/"+group, "", "If-Match", r.header.Get("ETag"))
		}
	})

	bobTok := e.exchange(e.user("bob").AccessToken, "read write") // Keycloak drops write
	e.want(e.call(bobTok, "GET", "/api/v1/groups/"+group, ""), 200, "")
	e.want(e.call(bobTok, "DELETE", "/api/v1/groups/"+group, "", "If-Match", etag), 403, "insufficient_scope")

	e.want(e.call(aliceTok, "DELETE", "/api/v1/groups/"+group, "", "If-Match", etag), 204, "")
	e.checkLog(func(rec map[string]any) bool {
		caller, _ := rec["caller"].(map[string]any)
		return rec["name"] == group && rec["action"] == "createGroup" && rec["result"] == "success" &&
			caller["username"] == "alice" && caller["azp"] == "tasmofleet-test"
	})
}

// Full write path with msm-test-rw; the new client logs in at the broker.
func TestWriteFlow(t *testing.T) {
	e := setup(t)
	rw := e.serviceAccount("msm-test-rw")
	id := randomID()
	role, dev := "tf_role_e2e_"+id, "e2e-"+id
	t.Cleanup(func() {
		for _, p := range []string{"/api/v1/clients/" + dev, "/api/v1/roles/" + role} {
			if r := e.call(rw, "GET", p, ""); r.status == 200 {
				e.call(rw, "DELETE", p, "", "If-Match", r.header.Get("ETag"))
			}
		}
	})

	info := e.want(e.call(rw, "GET", "/api/v1/info", ""), 200, "")
	version, _ := info.body["broker"].(map[string]any)["version"].(string)
	substitutesU := !strings.HasPrefix(version, "2.0.") // %u from Mosquitto 2.1 on

	e.want(e.call(rw, "POST", "/api/v1/roles", `{"rolename":"`+role+`","acls":[
		{"acltype":"subscribePattern","topic":"cmnd/%u/#","allow":true},
		{"acltype":"subscribePattern","topic":"e2e/`+id+`/#","allow":true}]}`), 201, "")
	r := e.want(e.call(rw, "POST", "/api/v1/clients", `{"username":"`+dev+`","roles":[{"rolename":"`+role+`"}]}`), 201, "")
	password, _ := r.body["password"].(string)
	e.secrets = append(e.secrets, password)
	if len(password) != 24 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("password %q, Cache-Control %q", password, r.header.Get("Cache-Control"))
	}

	if e.broker != "" {
		codes := subscribeCodes(t, e.broker, dev, password, []string{"e2e/" + id + "/x", "cmnd/" + dev + "/POWER", "cmnd/other/POWER"})
		if codes[0] >= 0x80 || codes[2] < 0x80 || (substitutesU && codes[1] >= 0x80) {
			t.Errorf("SUBACK % x, want granted, granted, refused", codes)
		}
	} else {
		t.Log("PMSS_TEST_BROKER_PLAIN not set; login not checked")
	}

	// Export contains the managed objects and no unmanaged ones.
	ex := e.want(e.call(rw, "GET", "/api/v1/export", ""), 200, "")
	names := map[string]bool{}
	for _, list := range []string{"clients", "roles"} {
		for _, o := range ex.body[list].([]any) {
			m := o.(map[string]any)
			for _, k := range []string{"username", "rolename"} {
				if n, ok := m[k].(string); ok {
					names[n] = true
				}
			}
		}
	}
	if !names[dev] || !names[role] || names["legacy-shared-user"] || names["pmss-admin"] {
		t.Errorf("export names %v", names)
	}

	// Unmanaged and reserved objects stay untouchable.
	e.want(e.call(rw, "DELETE", "/api/v1/clients/legacy-shared-user", "", "If-Match", `"x"`), 403, "not_managed")
	e.want(e.call(rw, "DELETE", "/api/v1/clients/pmss-admin", "", "If-Match", `"x"`), 403, "reserved_name")

	// Body over the limit.
	big := `{"groupname":"` + strings.Repeat("x", 1<<20) + `"}`
	e.want(e.call(rw, "POST", "/api/v1/groups", big), 413, "payload_too_large")

	// Delete: the client can no longer log in.
	r = e.want(e.call(rw, "GET", "/api/v1/clients/"+dev, ""), 200, "")
	e.want(e.call(rw, "DELETE", "/api/v1/clients/"+dev, "", "If-Match", r.header.Get("ETag")), 204, "")
	if e.broker != "" {
		if err := connectPlain(e.broker, dev, password); err == nil {
			t.Error("deleted client can still log in")
		}
	}
	r = e.want(e.call(rw, "GET", "/api/v1/roles/"+role, ""), 200, "")
	e.want(e.call(rw, "DELETE", "/api/v1/roles/"+role, "", "If-Match", r.header.Get("ETag")), 204, "")

	e.checkLog(func(rec map[string]any) bool {
		caller, _ := rec["caller"].(map[string]any)
		return rec["name"] == dev && rec["action"] == "createClient" && rec["result"] == "success" &&
			caller["azp"] == "msm-test-rw" && rec["after"] != nil
	})
}

// checkLog waits for a matching audit record (if match is set) and checks
// that no password or token of this test is in the log.
func (e *env) checkLog(match func(map[string]any) bool) {
	e.t.Helper()
	path := os.Getenv("PMSS_TEST_E2E_LOG")
	if path == "" {
		e.t.Log("PMSS_TEST_E2E_LOG not set; audit and log not checked")
		return
	}
	var data []byte
	found := match == nil
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			e.t.Fatal(err)
		}
		if !found {
			sc := bufio.NewScanner(bytes.NewReader(data))
			sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
			for sc.Scan() {
				var rec map[string]any
				if json.Unmarshal(sc.Bytes(), &rec) == nil && rec["log_type"] == "audit" && match(rec) {
					found = true
					break
				}
			}
		}
		if found || time.Now().After(deadline) {
			break
		}
	}
	if !found {
		e.t.Error("matching audit record not found in the log")
	}
	for _, s := range e.secrets {
		if s != "" && bytes.Contains(data, []byte(s)) {
			e.t.Errorf("secret (%d characters) found in the log", len(s))
		}
	}
}

// --- MQTT ---------------------------------------------------------------

func login(addr, user, password string) (*paho.Client, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, nil, err
	}
	cli := paho.NewClient(paho.ClientConfig{Conn: conn})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Connect(ctx, &paho.Connect{
		ClientID: user + "-e2e", CleanStart: true, KeepAlive: 10,
		Username: user, UsernameFlag: true, Password: []byte(password), PasswordFlag: true,
	}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return cli, conn, nil
}

func connectPlain(addr, user, password string) error {
	cli, conn, err := login(addr, user, password)
	if err != nil {
		return err
	}
	_ = cli.Disconnect(&paho.Disconnect{})
	conn.Close()
	return nil
}

func subscribeCodes(t *testing.T, addr, user, password string, topics []string) []byte {
	t.Helper()
	cli, conn, err := login(addr, user, password)
	if err != nil {
		t.Fatalf("login with the generated password: %v", err)
	}
	defer conn.Close()
	defer cli.Disconnect(&paho.Disconnect{})
	var subs []paho.SubscribeOptions
	for _, tp := range topics {
		subs = append(subs, paho.SubscribeOptions{Topic: tp})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sa, err := cli.Subscribe(ctx, &paho.Subscribe{Subscriptions: subs})
	if err != nil && sa == nil {
		t.Fatalf("subscribe: %v", err)
	}
	return sa.Reasons
}
