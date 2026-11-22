// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Noschvie/phylax-mqtt-security-service/internal/problem"
)

func TestPatchClient(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev","textname":"alt"}`), 201, "")
	tag := e.etag("/api/v1/clients/dev")

	rec := e.do(http.MethodPatch, "/api/v1/clients/dev", `{"textname":"Wohnzimmer"}`, "If-Match", tag)
	b := e.status(rec, 200, "")
	if b["textname"] != "Wohnzimmer" || b["textdescription"] != marker || rec.Header().Get("ETag") == tag {
		t.Errorf("patch: %v", b)
	}
	if e.fb.clients["dev"].Textdescription != marker {
		t.Error("marker lost")
	}
	tag = rec.Header().Get("ETag")
	b = e.status(e.do(http.MethodPatch, "/api/v1/clients/dev", `{"textdescription":"x"}`, "If-Match", tag), 422, problem.ValidationFailed)
	if errs := b["errors"].([]any); errs[0].(map[string]any)["code"] != "read_only" {
		t.Errorf("errors %v", errs)
	}
	e.status(e.do(http.MethodPatch, "/api/v1/clients/dev", `{}`, "If-Match", tag), 422, problem.ValidationFailed)
	e.status(e.do(http.MethodPatch, "/api/v1/clients/dev", `{"textname":"x"}`), 428, problem.PreconditionRequired)
	e.status(e.do(http.MethodPatch, "/api/v1/clients/legacy-shared-user", `{"textname":"x"}`, "If-Match", e.etag("/api/v1/clients/legacy-shared-user")), 403, problem.NotManaged)
}

func TestEnableDisable(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"dev"}`), 201, "")
	enabled := e.etag("/api/v1/clients/dev")

	rec := e.do(http.MethodPost, "/api/v1/clients/dev/disable", "", "If-Match", enabled)
	b := e.status(rec, 200, "")
	disabled := rec.Header().Get("ETag")
	if b["disabled"] != true || !e.fb.clients["dev"].Disabled || disabled == enabled {
		t.Errorf("disable: %v", b)
	}
	// Already disabled: nothing sent.
	n := len(e.fb.calls)
	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/disable", "", "If-Match", disabled), 200, "")
	if strings.Contains(strings.Join(e.fb.calls[n:], ","), "disableClient") {
		t.Error("disableClient sent twice")
	}
	rec = e.do(http.MethodPost, "/api/v1/clients/dev/enable", "{}", "If-Match", disabled)
	e.status(rec, 200, "")
	if rec.Header().Get("ETag") != enabled || e.fb.clients["dev"].Disabled {
		t.Error("enable did not restore the state")
	}
	e.status(e.do(http.MethodPost, "/api/v1/clients/dev/disable", "", "If-Match", disabled), 412, problem.PreconditionFailed)
}

// Decision on open point 8.8, variant A: certificate clients are refused.
func TestDisableCertificateClientRefused(t *testing.T) {
	e := newEnv(t)
	e.status(e.do(http.MethodPost, "/api/v1/clients", `{"username":"CN=homeassistant,O=mqtt-apps"}`), 201, "")
	path := "/api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps"
	tag := e.etag(path)
	for _, op := range []string{"/disable", "/enable"} {
		b := e.status(e.do(http.MethodPost, path+op, "", "If-Match", tag), 409, problem.CertificateClient)
		if !strings.Contains(b["detail"].(string), "Delete the client") {
			t.Errorf("detail %v", b["detail"])
		}
	}
	if e.fb.sent("disableClient") || e.fb.sent("enableClient") {
		t.Error("command sent for a certificate client")
	}
	if a := e.lastAudit(); a["result"] != "failed" || a["code"] != "certificate_client" {
		t.Errorf("audit %v", a)
	}
}

func TestSingleACLs(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodPost, "/api/v1/roles", `{"rolename":"tf_role_ha","acls":[{"acltype":"publishClientReceive","topic":"stat/#","allow":true}]}`)
	e.status(rec, 201, "")
	tag := rec.Header().Get("ETag")

	rec = e.do(http.MethodPost, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD","allow":false}`, "If-Match", tag)
	b := e.status(rec, 200, "")
	if len(b["acls"].([]any)) != 2 {
		t.Errorf("acls %v", b["acls"])
	}
	w := b["warnings"].([]any)
	if len(w) != 1 || w[0].(map[string]any)["pointer"] != "/acls/1" {
		t.Errorf("warnings %v (pointer into the response list)", w)
	}
	tag = rec.Header().Get("ETag")

	e.status(e.do(http.MethodPost, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"publishClientReceive","topic":"stat/#","allow":false}`, "If-Match", tag), 409, problem.AlreadyExists)
	b = e.status(e.do(http.MethodPost, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"publishClientReceive","topic":"x"}`, "If-Match", tag), 422, problem.ValidationFailed)
	if errs := b["errors"].([]any); errs[0].(map[string]any)["pointer"] != "/allow" {
		t.Errorf("pointer %v", errs)
	}
	e.status(e.do(http.MethodPost, "/api/v1/roles/role_legacy/acls", `{"acltype":"publishClientReceive","topic":"x","allow":true}`, "If-Match", tag), 403, problem.NotManaged)

	rec = e.do(http.MethodDelete, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"publishClientReceive","topic":"stat/+/FILEDOWNLOAD"}`, "If-Match", tag)
	b = e.status(rec, 200, "")
	if len(b["acls"].([]any)) != 1 || len(e.fb.roles["tf_role_ha"].ACLs) != 1 {
		t.Errorf("after remove: %v", b["acls"])
	}
	tag = rec.Header().Get("ETag")
	e.status(e.do(http.MethodDelete, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"publishClientReceive","topic":"nothere"}`, "If-Match", tag), 404, problem.NotFound)
	e.status(e.do(http.MethodDelete, "/api/v1/roles/tf_role_ha/acls", `{"topic":"x"}`, "If-Match", tag), 422, problem.ValidationFailed)

	// Silently dropped by the broker → readback mismatch.
	e.fb.dropACLType = "subscribeLiteral"
	e.status(e.do(http.MethodPost, "/api/v1/roles/tf_role_ha/acls", `{"acltype":"subscribeLiteral","topic":"x","allow":true}`, "If-Match", tag), 500, problem.ReadbackMismatch)
}
