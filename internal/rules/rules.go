// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rules holds the checks of the write endpoints: name rules
// (design 5.4, SEC-23), password policy (SEC-28), ACL fields (A-7, SEC-30)
// and the warning for deny rules without higher priority (specification
// 3.6). All checks run before any command goes to the broker.
package rules

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Reserved names (design 5.4): admin identities and their role.
const (
	ReservedClientPrefix = "pmss-"
	ReservedRole         = "role_security_manager"
)

// Limits of names and texts. MQTT allows 65535 bytes for user names;
// shorter limits keep logs and the DynSec file readable.
const (
	MaxNameBytes     = 1024
	MaxTextnameBytes = 1024
	MaxTopicBytes    = 65535
	MaxPriority      = 100000
)

// Password policy (design 7.3, N-6): exactly 24 characters A–Z a–z 0–9.
// ';' and spaces would break "Backlog MqttUser …; MqttPassword …" on Tasmota.
const (
	PasswordLength   = 24
	PasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// ACL types accepted (A-7); DynSec would silently drop unknown ones.
var ACLTypes = []string{
	"publishClientSend", "publishClientReceive",
	"subscribeLiteral", "subscribePattern",
	"unsubscribeLiteral", "unsubscribePattern",
}

// IsCertificateClient: certificate clients of the app listener are named
// after the subject, CN=… (design 5.4).
func IsCertificateClient(username string) bool { return strings.HasPrefix(username, "CN=") }

// IsReservedClient reports names of admin identities (pmss-*).
func IsReservedClient(username string) bool { return strings.HasPrefix(username, ReservedClientPrefix) }

// CheckUsername returns "" or why the name of a new client is not allowed
// (apart from the reserved prefix, which is a 403).
func CheckUsername(name string) string {
	if msg := checkName(name); msg != "" {
		return msg
	}
	if IsCertificateClient(name) {
		// RFC 2253 subject from use_subject_as_username, e.g.
		// CN=homeassistant,O=mqtt-apps.
		if len(name) == len("CN=") {
			return "certificate client name has an empty CN"
		}
		return ""
	}
	// Password clients: no = or , so they can never take the name of a
	// certificate client (SEC-23); no MQTT wildcards or level separators,
	// because the name is used as topic level in %u rules.
	if strings.ContainsAny(name, "=,") {
		return "password clients must not contain '=' or ','; certificate clients start with 'CN='"
	}
	if strings.ContainsAny(name, "+#/") {
		return "must not contain '+', '#' or '/' (the name is used as topic level in %u rules)"
	}
	return ""
}

// CheckObjectName checks the name of a new role or group: the prefix of
// managed objects is required.
func CheckObjectName(name, prefix string) string {
	if msg := checkName(name); msg != "" {
		return msg
	}
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return fmt.Sprintf("must start with %q and continue after it", prefix)
	}
	return ""
}

func checkName(name string) string {
	switch {
	case name == "":
		return "required"
	case len(name) > MaxNameBytes:
		return fmt.Sprintf("longer than %d bytes", MaxNameBytes)
	case !utf8.ValidString(name):
		return "not valid UTF-8"
	case strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0:
		return "must not contain spaces or control characters"
	}
	return ""
}

// CheckTextname returns "" or why a textname is not allowed.
func CheckTextname(s string) string {
	switch {
	case len(s) > MaxTextnameBytes:
		return fmt.Sprintf("longer than %d bytes", MaxTextnameBytes)
	case !utf8.ValidString(s):
		return "not valid UTF-8"
	case strings.IndexFunc(s, unicode.IsControl) >= 0:
		return "must not contain control characters"
	}
	return ""
}

// CheckPassword returns "" or why a given password breaks the policy. The
// password itself is never part of the message.
func CheckPassword(p string) string {
	if len(p) != PasswordLength {
		return fmt.Sprintf("must be exactly %d characters", PasswordLength)
	}
	for i := 0; i < len(p); i++ {
		if strings.IndexByte(PasswordAlphabet, p[i]) < 0 {
			return "only A-Z, a-z and 0-9 are allowed"
		}
	}
	return ""
}

// GeneratePassword returns a password of the policy from crypto/rand
// (uniform, about 142 bits).
func GeneratePassword() (string, error) {
	b := make([]byte, PasswordLength)
	max := big.NewInt(int64(len(PasswordAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = PasswordAlphabet[n.Int64()]
	}
	return string(b), nil
}

// CheckPriority returns "" or why a priority is out of range.
func CheckPriority(p int) string {
	if p < -MaxPriority || p > MaxPriority {
		return fmt.Sprintf("must be between %d and %d", -MaxPriority, MaxPriority)
	}
	return ""
}

// CheckTopicFilter returns "" or why topic is not a valid MQTT topic
// filter: '#' only as the whole last level, '+' only as a whole level.
func CheckTopicFilter(topic string) string {
	switch {
	case topic == "":
		return "required"
	case len(topic) > MaxTopicBytes:
		return "too long"
	case !utf8.ValidString(topic):
		return "not valid UTF-8"
	case strings.ContainsRune(topic, 0):
		return "must not contain NUL"
	}
	levels := strings.Split(topic, "/")
	for i, l := range levels {
		if strings.Contains(l, "#") && (l != "#" || i != len(levels)-1) {
			return "'#' is only allowed as the whole last level"
		}
		if strings.Contains(l, "+") && l != "+" {
			return "'+' is only allowed as a whole level"
		}
	}
	return ""
}

// FiltersOverlap reports whether some topic matches both filters.
func FiltersOverlap(a, b string) bool {
	la, lb := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; ; i++ {
		switch {
		case i == len(la) && i == len(lb):
			return true
		case i < len(la) && la[i] == "#", i < len(lb) && lb[i] == "#":
			return true
		case i == len(la) || i == len(lb):
			// "a/#" also matches "a"; that case is covered above.
			return false
		case la[i] == "+" || lb[i] == "+" || la[i] == lb[i]:
			continue
		default:
			return false
		}
	}
}
