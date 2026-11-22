// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

// Read API against Mosquitto with Dynamic Security (test/integration/broker):
// export, single objects, ETag rules (S-3, S-4, S-5) with real DynSec data.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/api"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/auth"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/config"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/dynsec"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/model"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
	tb "github.com/Noschvie/phylax-mqtt-security-service/internal/testbroker"
	"github.com/Noschvie/phylax-mqtt-security-service/internal/testrecord"
)

type allowAll struct{}

func (allowAll) Authorize(r *http.Request, _ auth.Scope) (*http.Request, *problem.Problem) {
	return r, nil
}

// fixture: managed and unmanaged objects with unique names.
type fixture struct {
	dev, cert, legacy string // clients
	group             string
	roleA, roleB      string
	unmanagedRole     string
}

func setup(t *testing.T, c *dynsec.Client) fixture {
	t.Helper()
	id := tb.RandomName("")
	f := fixture{
		dev:           "it-" + id + "-dev",
		cert:          "CN=it-" + id + ",O=mqtt-apps",
		legacy:        "it-" + id + "-legacy",
		group:         "tf_group_it_" + id,
		roleA:         "tf_role_it_" + id + "_a",
		roleB:         "tf_role_it_" + id + "_b",
		unmanagedRole: "role_it_" + id,
	}
	marker := config.Default().Managed.ClientMarker
	tb.Must(t, c, tb.CreateRole{Rolename: f.roleA, Textname: "A", ACLs: []tb.ACL{
		{ACLType: "subscribePattern", Topic: "stat/#", Allow: true},
		{ACLType: "publishClientReceive", Topic: "stat/+/FILEDOWNLOAD", Allow: false, Priority: 10},
		{ACLType: "publishClientReceive", Topic: "stat/#", Allow: true},
	}})
	tb.Must(t, c, tb.CreateRole{Rolename: f.roleB})
	tb.Must(t, c, tb.CreateRole{Rolename: f.unmanagedRole})
	tb.Must(t, c, tb.CreateGroup{Groupname: f.group, Textname: "Gruppe"})
	tb.Must(t, c, tb.CreateClient{Username: f.dev, Password: "Q7mXr2Lk9pTz4WbN8cVd3HsF", Textname: "Gerät", Textdescription: marker,
		Roles: []tb.RoleRef{{Rolename: f.roleA}}})
	tb.Must(t, c, tb.CreateClient{Username: f.cert, Textdescription: marker})
	tb.Must(t, c, tb.CreateClient{Username: f.legacy, Password: "Q7mXr2Lk9pTz4WbN8cVd3HsF", Roles: []tb.RoleRef{{Rolename: f.unmanagedRole}}})
	tb.Must(t, c, tb.AddGroupRole{Groupname: f.group, Rolename: f.roleB})
	t.Cleanup(func() {
		for _, cmd := range []dynsec.Command{
			tb.DeleteClient{Username: f.dev}, tb.DeleteClient{Username: f.cert}, tb.DeleteClient{Username: f.legacy},
			tb.DeleteGroup{Groupname: f.group},
			tb.DeleteRole{Rolename: f.roleA}, tb.DeleteRole{Rolename: f.roleB}, tb.DeleteRole{Rolename: f.unmanagedRole},
		} {
			_, _ = c.Execute(context.Background(), cmd) // t.Context is already cancelled here
		}
	})
	return f
}

func newServer(t *testing.T, c *dynsec.Client, brokerVersion *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(testrecord.Handler(api.NewHandler(api.Options{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:         "it",
		Managed:         config.Default().Managed,
		MaxRequestBytes: config.MinRequestBytes,
		DynSec:          c,
		Auth:            allowAll{},
		BrokerVersion:   func() string { v, _ := brokerVersion.Load().(string); return v },
	})))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

type export struct {
	ExportedAt string         `json:"exportedAt"`
	Clients    []model.Client `json:"clients"`
	Groups     []model.Group  `json:"groups"`
	Roles      []model.Role   `json:"roles"`
}

func getExport(t *testing.T, srv *httptest.Server) (export, []byte) {
	t.Helper()
	status, _, body := get(t, srv, "/api/v1/export")
	if status != 200 {
		t.Fatalf("export: %d %s", status, body)
	}
	var e export
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatal(err)
	}
	return e, body
}

func etagOf(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	status, h, body := get(t, srv, path)
	if status != 200 {
		t.Fatalf("%s: %d %s", path, status, body)
	}
	return h.Get("ETag")
}

func TestIntegrationReadAPI(t *testing.T) {
	b := tb.FromEnv(t)
	var brokerVersion atomic.Value
	_, c := tb.Connect(t, b, tb.Options{
		Cert: "pmss-admin", WaitReady: true, ExtraTopics: []string{"$SYS/broker/version"},
		OnExtra: func(_ string, p []byte) { brokerVersion.Store(string(p)) },
	})
	f := setup(t, c)
	srv := newServer(t, c, &brokerVersion)

	// Info: broker version from $SYS (retained).
	tb.WaitFor(t, 5*time.Second, func() bool { v, _ := brokerVersion.Load().(string); return v != "" }, "$SYS/broker/version")
	_, _, body := get(t, srv, "/api/v1/info")
	if !strings.Contains(string(body), `"product":"mosquitto","version":"mosquitto version 2.`) {
		t.Errorf("info %s", body)
	}

	// Export: managed objects only, sorted.
	e, raw := getExport(t, srv)
	usernames := func(e export) (out []string) {
		for _, c := range e.Clients {
			out = append(out, c.Username)
		}
		return
	}
	got := usernames(e)
	if !slices.Contains(got, f.dev) || !slices.Contains(got, f.cert) || slices.Contains(got, f.legacy) || slices.Contains(got, "pmss-admin") {
		t.Errorf("export clients %v", got)
	}
	if !slices.IsSorted(got) {
		t.Errorf("clients not sorted: %v", got)
	}
	var roleNames []string
	for _, r := range e.Roles {
		roleNames = append(roleNames, r.Rolename)
	}
	if !slices.Contains(roleNames, f.roleA) || slices.Contains(roleNames, f.unmanagedRole) || slices.Contains(roleNames, "role_security_manager") {
		t.Errorf("export roles %v", roleNames)
	}
	for _, r := range e.Roles {
		if r.Rolename == f.roleA {
			want := []model.ACL{
				{ACLType: "publishClientReceive", Topic: "stat/#", Allow: true, Priority: 0},
				{ACLType: "publishClientReceive", Topic: "stat/+/FILEDOWNLOAD", Allow: false, Priority: 10},
				{ACLType: "subscribePattern", Topic: "stat/#", Allow: true, Priority: 0},
			}
			if !slices.Equal(r.ACLs, want) {
				t.Errorf("acls %+v", r.ACLs)
			}
		}
	}
	for _, cl := range e.Clients {
		if cl.Username == f.cert && cl.AuthType != model.AuthCertificate {
			t.Errorf("authType %s", cl.AuthType)
		}
	}

	// Two exports of the same state are byte-identical apart from exportedAt.
	_, raw2 := getExport(t, srv)
	stamp := regexp.MustCompile(`"exportedAt":"[^"]*"`)
	if stamp.ReplaceAllString(string(raw), "") != stamp.ReplaceAllString(string(raw2), "") {
		t.Error("two exports of the same state differ")
	}

	// Single objects: ETag header = etag in the export; URL-encoded CN= name.
	clientPath := "/api/v1/clients/" + url.PathEscape(f.dev)
	certPath := "/api/v1/clients/" + strings.NewReplacer("=", "%3D", ",", "%2C").Replace(f.cert)
	groupPath := "/api/v1/groups/" + f.group
	for _, cl := range e.Clients {
		if cl.Username == f.dev && etagOf(t, srv, clientPath) != cl.ETag {
			t.Error("client ETag differs from the export")
		}
	}
	status, _, body := get(t, srv, certPath)
	if status != 200 || !strings.Contains(string(body), `"username":"`+f.cert+`"`) || !strings.Contains(string(body), `"managed":true`) {
		t.Errorf("certificate client: %d %s", status, body)
	}
	status, _, body = get(t, srv, "/api/v1/clients/"+f.legacy)
	if status != 200 || !strings.Contains(string(body), `"managed":false`) {
		t.Errorf("unmanaged client: %d %s", status, body)
	}

	// S-4: group membership changes only the group ETag.
	clientETag, groupETag := etagOf(t, srv, clientPath), etagOf(t, srv, groupPath)
	tb.Must(t, c, tb.AddGroupClient{Groupname: f.group, Username: f.dev})
	if etagOf(t, srv, clientPath) != clientETag {
		t.Error("client ETag changed by group membership")
	}
	if etagOf(t, srv, groupPath) == groupETag {
		t.Error("group ETag unchanged by a new member")
	}
	status, _, body = get(t, srv, clientPath)
	if status != 200 || !strings.Contains(string(body), `"groups":[{"groupname":"`+f.group+`","priority":-1}]`) {
		t.Errorf("client shows no group: %s", body)
	}

	// Role assignment changes the client ETag; removing it restores it.
	tb.Must(t, c, tb.AddClientRole{Username: f.dev, Rolename: f.roleB})
	if etagOf(t, srv, clientPath) == clientETag {
		t.Error("client ETag unchanged by a new role")
	}
	tb.Must(t, c, tb.RemoveClientRole{Username: f.dev, Rolename: f.roleB})
	if etagOf(t, srv, clientPath) != clientETag {
		t.Error("client ETag not restored after removing the role")
	}

	// disabled: left out by DynSec when false, so disable + enable restores.
	tb.Must(t, c, tb.DisableClient{Username: f.dev})
	if etagOf(t, srv, clientPath) == clientETag {
		t.Error("client ETag unchanged by disable")
	}
	tb.Must(t, c, tb.EnableClient{Username: f.dev})
	if etagOf(t, srv, clientPath) != clientETag {
		t.Error("client ETag not restored after enable")
	}

	// Not found.
	status, h, _ := get(t, srv, "/api/v1/roles/tf_role_missing_"+tb.RandomName(""))
	if status != 404 || h.Get("Content-Type") != "application/problem+json" {
		t.Errorf("missing role: %d %s", status, h.Get("Content-Type"))
	}
}

// TestIntegrationPasswordChangeKeepsETag: S-5 with the real broker.
func TestIntegrationPasswordChangeKeepsETag(t *testing.T) {
	b := tb.FromEnv(t)
	_, c := tb.Connect(t, b, tb.Options{Cert: "pmss-admin", WaitReady: true})
	f := setup(t, c)
	srv := newServer(t, c, &atomic.Value{})
	path := "/api/v1/clients/" + f.dev
	before := etagOf(t, srv, path)
	tb.Must(t, c, setClientPassword{Username: f.dev, Password: "h3RtY8vQm2NpXc6KzL4bWs9D"})
	if etagOf(t, srv, path) != before {
		t.Error("password change changed the ETag")
	}
}

type setClientPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (setClientPassword) CommandName() string { return "setClientPassword" }
