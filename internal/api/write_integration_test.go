// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

// Write API against Mosquitto with Dynamic Security: the flow of
// specification 5 (role per device, client with generated password) and
// the rights of the created client at a password listener.
//
//	PMSS_TEST_BROKER_PLAIN  host:port of the password listener, e.g. 127.0.0.1:18883

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"

	tb "github.com/Noschvie/phylax-mqtt-security-service/internal/testbroker"
)

func send(t *testing.T, srv *httptest.Server, method, path, body string, headers ...string) (int, http.Header, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, resp.Header, m
}

func must(t *testing.T, want, got int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d: %v", got, want, body)
	}
}

func TestIntegrationWriteFlow(t *testing.T) {
	b := tb.FromEnv(t)
	var version atomic.Value
	_, c := tb.Connect(t, b, tb.Options{
		Cert: "pmss-admin", WaitReady: true, ExtraTopics: []string{"$SYS/broker/version"},
		OnExtra: func(_ string, p []byte) { version.Store(string(p)) },
	})
	srv := newServer(t, c, &version)
	tb.WaitFor(t, 5*time.Second, func() bool { v, _ := version.Load().(string); return v != "" }, "$SYS/broker/version")
	// %u in DynSec ACLs is substituted from Mosquitto 2.1 on (2.0.18 refuses).
	substitutesU := !strings.HasPrefix(version.Load().(string), "mosquitto version 2.0.")
	id := tb.RandomName("")
	role, devRole, group, dev := "tf_role_it_"+id, "tf_role_dev_"+id, "tf_group_it_"+id, "it-"+id
	t.Cleanup(func() {
		for _, cmd := range []any{tb.DeleteClient{Username: dev}, tb.DeleteGroup{Groupname: group}, tb.DeleteRole{Rolename: role}, tb.DeleteRole{Rolename: devRole}} {
			_, _ = c.Execute(context.Background(), cmd.(interface{ CommandName() string }))
		}
	})

	// Roles: profile with %u and the device role with a deny rule.
	st, _, body := send(t, srv, "POST", "/api/v1/roles", `{"rolename":"`+role+`","textname":"Tasmota","acls":[
		{"acltype":"publishClientSend","topic":"stat/%u/#","allow":true},
		{"acltype":"subscribePattern","topic":"cmnd/%u/#","allow":true}]}`)
	must(t, 201, st, body)
	st, _, body = send(t, srv, "POST", "/api/v1/roles", `{"rolename":"`+devRole+`","acls":[
		{"acltype":"subscribePattern","topic":"cmnd/wohnzimmer/#","allow":true},
		{"acltype":"subscribePattern","topic":"cmnd/wohnzimmer/secret","allow":false}]}`)
	must(t, 201, st, body)
	if w, _ := body["warnings"].([]any); len(w) != 1 {
		t.Errorf("warnings %v", body["warnings"])
	}
	st, _, body = send(t, srv, "POST", "/api/v1/groups", `{"groupname":"`+group+`"}`)
	must(t, 201, st, body)

	// Client with role and group, generated password.
	st, h, body := send(t, srv, "POST", "/api/v1/clients", `{"username":"`+dev+`","textname":"Gerät","roles":[{"rolename":"`+devRole+`"}],"groups":[{"groupname":"`+group+`"}]}`)
	must(t, 201, st, body)
	password, _ := body["password"].(string)
	clientETag := h.Get("ETag")
	if len(password) != 24 || clientETag == "" {
		t.Fatalf("password %q ETag %q", password, clientETag)
	}

	// createClient is atomic in Mosquitto: an unknown role creates nothing.
	missing := "it-" + id + "-missing"
	st, _, body = send(t, srv, "POST", "/api/v1/clients", `{"username":"`+missing+`","roles":[{"rolename":"tf_role_missing_`+id+`"}]}`)
	must(t, 422, st, body)
	if body["code"] != "unknown_role" || body["clientExists"] != false {
		t.Errorf("unknown role: %v", body)
	}
	if st, _, _ := send(t, srv, "GET", "/api/v1/clients/"+missing, ""); st != 404 {
		t.Errorf("client exists after unknown_role: %d", st)
	}

	// Group gets the profile role; the client ETag stays (S-4).
	st, h, body = send(t, srv, "GET", "/api/v1/groups/"+group, "")
	must(t, 200, st, body)
	st, _, body = send(t, srv, "POST", "/api/v1/groups/"+group+"/roles", `{"rolename":"`+role+`"}`, "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if _, h, _ := send(t, srv, "GET", "/api/v1/clients/"+dev, ""); h.Get("ETag") != clientETag {
		t.Error("client ETag changed by a group role")
	}

	// The client logs in with the generated password and has exactly its rights.
	if addr := os.Getenv("PMSS_TEST_BROKER_PLAIN"); addr != "" {
		codes := subscribeCodes(t, addr, dev, password, []string{
			"cmnd/" + dev + "/POWER", // tf_role_…: cmnd/%u/#
			"cmnd/wohnzimmer/POWER",  // device role
			"cmnd/other-device/POWER",
			"stat/#",
		})
		if codes[1] >= 0x80 || codes[2] < 0x80 || codes[3] < 0x80 {
			t.Errorf("SUBACK codes % x, want (granted), granted, refused, refused", codes)
		}
		if substitutesU && codes[0] >= 0x80 {
			t.Errorf("cmnd/%%u/# not granted for %s: % x", dev, codes)
		} else if !substitutesU {
			t.Logf("%s: %%u not substituted, check skipped", version.Load())
		}
	} else {
		t.Log("PMSS_TEST_BROKER_PLAIN not set; login of the created client not checked")
	}

	// Password change: ETag unchanged (S-5); the old password stops working.
	st, h, body = send(t, srv, "POST", "/api/v1/clients/"+dev+"/password", `{}`, "If-Match", clientETag)
	must(t, 200, st, body)
	newPassword, _ := body["password"].(string)
	if h.Get("ETag") != clientETag || newPassword == "" || newPassword == password {
		t.Errorf("password change: %v %s", body, h.Get("ETag"))
	}
	if addr := os.Getenv("PMSS_TEST_BROKER_PLAIN"); addr != "" {
		if err := connectPlain(addr, dev, password); err == nil {
			t.Error("old password still accepted")
		}
		if err := connectPlain(addr, dev, newPassword); err != nil {
			t.Errorf("new password refused: %v", err)
		}
	}

	// Replace the ACLs of the device role; stale If-Match → 412.
	st, h, body = send(t, srv, "GET", "/api/v1/roles/"+devRole, "")
	must(t, 200, st, body)
	roleETag := h.Get("ETag")
	st, h, body = send(t, srv, "PUT", "/api/v1/roles/"+devRole+"/acls", `{"acls":[{"acltype":"subscribePattern","topic":"cmnd/kueche/#","allow":true}]}`, "If-Match", roleETag)
	must(t, 200, st, body)
	if h.Get("ETag") == roleETag || len(body["acls"].([]any)) != 1 {
		t.Errorf("acls not replaced: %v", body)
	}
	st, _, body = send(t, srv, "PUT", "/api/v1/roles/"+devRole+"/acls", `{"acls":[]}`, "If-Match", roleETag)
	must(t, 412, st, body)

	// A change by mosquitto_ctrl (break-glass) between GET and change → 412.
	tb.Must(t, c, tb.AddClientRole{Username: dev, Rolename: role})
	st, _, body = send(t, srv, "DELETE", "/api/v1/clients/"+dev, "", "If-Match", clientETag)
	must(t, 412, st, body)

	// Unmanaged objects cannot be changed (403).
	st, _, body = send(t, srv, "DELETE", "/api/v1/clients/pmss-breakglass-admin", "", "If-Match", `"x"`)
	must(t, 403, st, body)
	st, _, body = send(t, srv, "DELETE", "/api/v1/roles/role_security_manager", "", "If-Match", `"x"`)
	must(t, 403, st, body)

	// Delete with the current ETag; the broker drops the connection of the client.
	_, h, _ = send(t, srv, "GET", "/api/v1/clients/"+dev, "")
	st, _, body = send(t, srv, "DELETE", "/api/v1/clients/"+dev, "", "If-Match", h.Get("ETag"))
	must(t, 204, st, body)
	if addr := os.Getenv("PMSS_TEST_BROKER_PLAIN"); addr != "" {
		if err := connectPlain(addr, dev, newPassword); err == nil {
			t.Error("deleted client can still log in")
		}
	}
	for _, p := range []string{"/api/v1/groups/" + group, "/api/v1/roles/" + role, "/api/v1/roles/" + devRole} {
		_, h, _ := send(t, srv, "GET", p, "")
		st, _, body := send(t, srv, "DELETE", p, "", "If-Match", h.Get("ETag"))
		must(t, 204, st, body)
	}
}

func connectPlain(addr, user, password string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	cli := paho.NewClient(paho.ClientConfig{Conn: conn})
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ca, err := cli.Connect(ctx, &paho.Connect{
		ClientID: user + "-it", CleanStart: true, KeepAlive: 10,
		Username: user, UsernameFlag: true, Password: []byte(password), PasswordFlag: true,
	})
	if err != nil {
		return err
	}
	_ = ca
	_ = cli.Disconnect(&paho.Disconnect{})
	return nil
}

// subscribeCodes logs in with user/password and returns the SUBACK reason
// code of every topic filter.
func subscribeCodes(t *testing.T, addr, user, password string, topics []string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := paho.NewClient(paho.ClientConfig{Conn: conn})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Connect(ctx, &paho.Connect{
		ClientID: user + "-it", CleanStart: true, KeepAlive: 10,
		Username: user, UsernameFlag: true, Password: []byte(password), PasswordFlag: true,
	}); err != nil {
		t.Fatalf("login with the generated password: %v", err)
	}
	defer cli.Disconnect(&paho.Disconnect{})
	var subs []paho.SubscribeOptions
	for _, tp := range topics {
		subs = append(subs, paho.SubscribeOptions{Topic: tp, QoS: 0})
	}
	sa, err := cli.Subscribe(ctx, &paho.Subscribe{Subscriptions: subs})
	if err != nil && sa == nil {
		t.Fatalf("subscribe: %v", err)
	}
	return sa.Reasons
}

// PMSS extras (design 7.3) against the real broker.
func TestIntegrationWriteExtras(t *testing.T) {
	b := tb.FromEnv(t)
	var version atomic.Value
	_, c := tb.Connect(t, b, tb.Options{
		Cert: "pmss-admin", WaitReady: true, ExtraTopics: []string{"$SYS/broker/version"},
		OnExtra: func(_ string, p []byte) { version.Store(string(p)) },
	})
	srv := newServer(t, c, &version)
	id := tb.RandomName("")
	dev, cert, role := "it-x-"+id, "CN=it-x-"+id+",O=mqtt-apps", "tf_role_x_"+id
	t.Cleanup(func() {
		for _, cmd := range []any{tb.DeleteClient{Username: dev}, tb.DeleteClient{Username: cert}, tb.DeleteRole{Rolename: role}} {
			_, _ = c.Execute(context.Background(), cmd.(interface{ CommandName() string }))
		}
	})

	st, h, body := send(t, srv, "POST", "/api/v1/clients", `{"username":"`+dev+`","textname":"alt"}`)
	must(t, 201, st, body)
	password, _ := body["password"].(string)

	// PATCH textname; the marker stays.
	st, h, body = send(t, srv, "PATCH", "/api/v1/clients/"+dev, `{"textname":"neu"}`, "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if body["textname"] != "neu" || body["managed"] != true {
		t.Errorf("patch: %v", body)
	}

	// Disable: the password client can no longer log in; enable restores it.
	st, h, body = send(t, srv, "POST", "/api/v1/clients/"+dev+"/disable", "", "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if body["disabled"] != true {
		t.Errorf("disable: %v", body)
	}
	addr := os.Getenv("PMSS_TEST_BROKER_PLAIN")
	if addr != "" {
		if err := connectPlain(addr, dev, password); err == nil {
			t.Error("disabled client can still log in")
		}
	}
	st, _, body = send(t, srv, "POST", "/api/v1/clients/"+dev+"/enable", "", "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if addr != "" {
		if err := connectPlain(addr, dev, password); err != nil {
			t.Errorf("enabled client refused: %v", err)
		}
	}

	// Decision 8.8 A: certificate clients cannot be disabled.
	st, _, body = send(t, srv, "POST", "/api/v1/clients", `{"username":"`+cert+`"}`)
	must(t, 201, st, body)
	certPath := "/api/v1/clients/" + url.PathEscape(cert)
	_, h, _ = send(t, srv, "GET", certPath, "")
	st, _, body = send(t, srv, "POST", certPath+"/disable", "", "If-Match", h.Get("ETag"))
	must(t, 409, st, body)
	if body["code"] != "certificate_client" {
		t.Errorf("certificate disable: %v", body)
	}

	// Single ACLs: add, duplicate → 409, remove, missing → 404.
	st, h, body = send(t, srv, "POST", "/api/v1/roles", `{"rolename":"`+role+`","acls":[{"acltype":"subscribePattern","topic":"cmnd/a/#","allow":true}]}`)
	must(t, 201, st, body)
	acl := `{"acltype":"subscribePattern","topic":"cmnd/a/secret","allow":false}`
	st, h, body = send(t, srv, "POST", "/api/v1/roles/"+role+"/acls", acl, "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if len(body["acls"].([]any)) != 2 || len(body["warnings"].([]any)) != 1 {
		t.Errorf("add acl: %v", body)
	}
	st, _, body = send(t, srv, "POST", "/api/v1/roles/"+role+"/acls", acl, "If-Match", h.Get("ETag"))
	must(t, 409, st, body)
	st, h, body = send(t, srv, "DELETE", "/api/v1/roles/"+role+"/acls", `{"acltype":"subscribePattern","topic":"cmnd/a/secret"}`, "If-Match", h.Get("ETag"))
	must(t, 200, st, body)
	if len(body["acls"].([]any)) != 1 {
		t.Errorf("remove acl: %v", body)
	}
	st, _, body = send(t, srv, "DELETE", "/api/v1/roles/"+role+"/acls", `{"acltype":"subscribePattern","topic":"cmnd/a/secret"}`, "If-Match", h.Get("ETag"))
	must(t, 404, st, body)
}
