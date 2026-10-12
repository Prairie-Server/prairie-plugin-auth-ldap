package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-ldap/ldap/v3"
	pluginv1 "github.com/prairie-server/prairie-plugin-sdk/pkg/pluginproto/prairie/plugin/v1"
)

func TestParseConfigReportsMoreProblems(t *testing.T) {
	t.Parallel()
	good := map[string]any{"urls": "ldaps://x"}
	users := map[string]any{"base_dn": "dc=x"}
	for _, tc := range []struct {
		name      string
		directory map[string]any
		users     map[string]any
		groups    map[string]any
		want      string
	}{
		{"url without host", map[string]any{"urls": "ldaps://:636"}, users, nil, "host is required"},
		{"unknown group source", good, users, map[string]any{"source": "bogus"}, `group source "bogus"`},
		{"bad membership attribute", good, users, map[string]any{"source": "memberof", "membership_attribute": "member of"}, "group membership attribute"},
		{"bad group base dn", good, users, map[string]any{"source": "search", "base_dn": "cn=a,,dc=x"}, "group base DN is not a valid DN"},
		{"bad group name attribute", good, users, map[string]any{"source": "search", "name_attribute": "cn name"}, "group name attribute"},
		{"bad allowed groups", good, users, map[string]any{"allowed_groups": "cn=a,,dc=x"}, "allowed groups"},
		{"unknown email trust", good, map[string]any{"base_dn": "dc=x", "email_verified": "maybe"}, nil, "email verification value"},
		{"timeout not a number", map[string]any{"urls": "ldaps://x", "connect_timeout_seconds": "soon"}, users, nil, "must be a number of seconds"},
		{"timeout wrong type", map[string]any{"urls": "ldaps://x", "connect_timeout_seconds": true}, users, nil, "must be a number of seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := []*pluginv1.ConfigEntry{entry(t, configKeyDirectory, tc.directory), entry(t, configKeyUsers, tc.users)}
			if tc.groups != nil {
				entries = append(entries, entry(t, configKeyGroups, tc.groups))
			}
			s := ParseConfig(entries)
			if s.Ready() || !strings.Contains(s.ProblemSummary(), tc.want) {
				t.Fatalf("problems = %q, want one containing %q", s.ProblemSummary(), tc.want)
			}
		})
	}
}

func TestParseConfigReadsLooselyTypedValues(t *testing.T) {
	t.Parallel()
	s := ParseConfig([]*pluginv1.ConfigEntry{
		entry(t, configKeyDirectory, map[string]any{
			"urls":                    "ldap://x",
			"start_tls":               " TRUE ",
			"connect_timeout_seconds": "7",
			"request_timeout_seconds": "  ",
		}),
		entry(t, configKeyUsers, map[string]any{"base_dn": "dc=x"}),
	})
	if !s.Ready() || !s.StartTLS || s.ConnectTimeout.Seconds() != 7 || s.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("settings = %+v, problems = %q", s, s.ProblemSummary())
	}
	if got := durationValue(map[string]any{"k": -3.0}, "k", defaultRequestTimeout, func(string, ...any) {}); got != defaultRequestTimeout {
		t.Fatalf("a non-positive timeout must fall back, got %v", got)
	}
}

func TestSettingsNilSafety(t *testing.T) {
	t.Parallel()
	var s *Settings
	if s.Issuer() != "" || s.Ready() || s.ProblemSummary() == "" {
		t.Fatal("a nil Settings must report as unconfigured")
	}
	if (&Settings{}).Issuer() != "" {
		t.Fatal("no URLs means no issuer")
	}
}

func TestStringValueAndTemplateHelpers(t *testing.T) {
	t.Parallel()
	m := map[string]any{"f": 2.5, "yes": true, "no": false, "list": []any{"a", 3.0, "b"}}
	for key, want := range map[string]string{"f": "2.5", "yes": "true", "no": "false", "list": "a\nb", "missing": ""} {
		if got := stringValue(m, key); got != want {
			t.Errorf("stringValue(%q) = %q, want %q", key, got, want)
		}
	}
	if err := validateTemplateFilter("  ", usernamePlaceholder); err == nil {
		t.Fatal("a blank filter must be refused")
	}
	if validAttributeName("") {
		t.Fatal("an empty attribute name is not valid")
	}
}

func TestClassifyBindErrorMoreCases(t *testing.T) {
	t.Parallel()
	if got := classifyBindError(errors.New("dial tcp: refused"), nil); got.code != pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE {
		t.Fatalf("non-LDAP error = %v", got.code)
	}
	if got := classifyBindError(ldap.NewError(49, errors.New("Account is locked")), nil); got.code != pluginv1.AuthDenial_AUTH_DENIAL_ACCOUNT_DISABLED {
		t.Fatalf("locked account = %v", got.code)
	}
	if got := classifyBindError(ldap.NewError(19, errors.New("password expired")), nil); got.code != pluginv1.AuthDenial_AUTH_DENIAL_PASSWORD_EXPIRED {
		t.Fatalf("expired constraint violation = %v", got.code)
	}
	if diagnosticMessage(nil) != "" || diagnosticMessage(&ldap.Error{}) != "" {
		t.Fatal("a missing error has no diagnostic")
	}
	if orNone("") != "no diagnostic message" || orNone("x") != "x" {
		t.Fatal("orNone must only replace empty text")
	}
}

func TestDNComparison(t *testing.T) {
	t.Parallel()
	parse := func(s string) *ldap.DN {
		dn, err := ldap.ParseDN(s)
		if err != nil {
			t.Fatal(err)
		}
		return dn
	}
	if dnEqualFold(nil, parse("cn=a")) || dnEqualFold(parse("cn=a"), parse("cn=a,dc=x")) {
		t.Fatal("different shapes must differ")
	}
	if dnEqualFold(parse("cn=a+uid=b"), parse("cn=a,dc=x")) || dnEqualFold(parse("cn=a+uid=b"), parse("cn=a+uid=c")) {
		t.Fatal("multi-valued RDNs must compare every attribute")
	}
	if !dnEqualFold(parse("cn=a+uid=b"), parse("UID=B+CN=A")) {
		t.Fatal("multi-valued RDN order must not matter")
	}
	if !sameDN("CN=a, DC=x", "cn=A,dc=X") || sameDN("cn=a,dc=x", "cn=b,dc=x") || sameDN("not a dn", "cn=a") {
		t.Fatal("sameDN misjudged")
	}
	ref, _ := parseGroupRefs("cn=a,dc=x")
	if ref[0].String() != "cn=a,dc=x" {
		t.Fatalf("ref = %q", ref[0].String())
	}
	if got := groupNames([]directoryGroup{{}, groupFromDN("cn=ok,dc=x")}); len(got) != 1 || got[0] != "ok" {
		t.Fatalf("names = %v", got)
	}
}

func TestTLSVersionLabelsAndNilSession(t *testing.T) {
	t.Parallel()
	if tlsVersion(tls.VersionTLS12) != "(TLS 1.2)" || tlsVersion(tls.VersionTLS13) != "(TLS 1.3)" || tlsVersion(0) != "" {
		t.Fatal("tls version labels")
	}
	(*session)(nil).close()
	if err := (&session{settings: &Settings{}}).bindService(); err != nil {
		t.Fatalf("no service account means no bind: %v", err)
	}
}

func TestUniqueIDValueMissingBinaryAttribute(t *testing.T) {
	t.Parallel()
	got, err := uniqueIDValue(ldap.NewEntry("cn=a,dc=x", nil), "objectGUID")
	if got != "" || err != nil {
		t.Fatalf("missing GUID = %q, %v", got, err)
	}
}

func TestAssetRoutesAnswerHeadWithoutBody(t *testing.T) {
	t.Parallel()
	routes := NewAssetRoutes(fstest.MapFS{"ldap.svg": {Data: []byte("<svg/>")}})
	resp, err := routes.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodHead, Path: "/assets/ldap.svg"})
	if err != nil || resp.GetStatusCode() != http.StatusOK || len(resp.GetBody()) != 0 {
		t.Fatalf("HEAD = %v, %v", resp, err)
	}
}

func TestTestConnectionReportsFailoverAndAnonymousSearch(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	staged := testConfig(t, d, configOverrides{
		configKeyDirectory: {"urls": "ldaps://127.0.0.1:1\n" + d.url(), "bind_dn": nil, "bind_password": nil},
		configKeyGroups:    {"source": "search", "base_dn": testGroups},
		configKeyUsers:     {"test_username": "bob"},
	})
	resp, err := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: staged})
	if err != nil {
		t.Fatal(err)
	}
	var connect, bind string
	for _, step := range resp.GetSteps() {
		switch step.GetId() {
		case "connect":
			connect = step.GetMessage()
		case "service_bind":
			bind = step.GetMessage()
		}
	}
	if !strings.Contains(connect, "Unreachable first: ldaps://127.0.0.1:1") {
		t.Fatalf("connect message = %q", connect)
	}
	if !strings.Contains(bind, "anonymously") {
		t.Fatalf("service bind message = %q", bind)
	}
}

func TestAuthenticateIdentityOptions(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	d.setAttr("uid=alice,"+testPeople, "labeledURI", "https://img.example/alice.png")
	for _, tc := range []struct {
		trust string
		want  *bool
	}{{"verified", ptrBool(true)}, {"unverified", ptrBool(false)}} {
		p := newTestProvider(t, d, configOverrides{configKeyUsers: {
			"email_verified":         tc.trust,
			"picture_url_attribute":  "labeledURI",
			"username_attribute":     "title",
			"display_name_attribute": "description",
		}})
		resp := signIn(t, p, "alice", testPasswords["alice"])
		if resp.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED {
			t.Fatalf("sign-in denied: %v", resp.GetDenial())
		}
		if resp.GetEmailVerified() != *tc.want {
			t.Errorf("%s: email verified = %v", tc.trust, resp.GetEmailVerified())
		}
		if resp.GetUsername() != "alice" || resp.GetDisplayName() != "alice" {
			t.Errorf("fallback identity = %q / %q, want the sign-in name", resp.GetUsername(), resp.GetDisplayName())
		}
	}
}

func ptrBool(v bool) *bool { return &v }

func TestConnectWithoutURLsAndDefaultPorts(t *testing.T) {
	t.Parallel()
	if _, _, err := connect(context.Background(), &Settings{}); err == nil {
		t.Fatal("connect without a URL must fail")
	}
	for _, raw := range []string{"ldap://127.0.0.1", "ldaps://127.0.0.1"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		// Nothing listens on the default LDAP ports here; the point is that a
		// URL without a port is dialled on the scheme's default and fails
		// cleanly.
		if sess, err := dialOne(context.Background(), &Settings{}, u, 200*time.Millisecond); err == nil {
			sess.close()
		}
	}
	if _, err := (&session{}).bindUser("uid=a,dc=x", ""); err == nil {
		t.Fatal("an empty password must never reach the directory")
	}
}

func TestSignInAndCheckErrorPaths(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)

	// A service account the directory rejects makes every re-check unavailable.
	badBind := newTestProvider(t, d, configOverrides{configKeyDirectory: {"bind_password": "wrong"}})
	wantStatus(t, badBind, "uuid-alice", pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)

	// A user filter the directory truncates cannot identify one account.
	broad := newTestProvider(t, d, configOverrides{configKeyUsers: {"filter": "(|(uid={username})(uid=alice))"}})
	d.setServerSizeLimit(1)
	wantDenial(t, signIn(t, broad, "bob", testPasswords["bob"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
	d.setServerSizeLimit(0)

	// An entry without the unique ID attribute cannot be linked.
	noID := newTestProvider(t, d, configOverrides{configKeyUsers: {"unique_id_attribute": "title"}})
	wantDenial(t, signIn(t, noID, "alice", testPasswords["alice"]), pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE)
}

func TestTestConnectionTestUserOutcomes(t *testing.T) {
	d := startFakeDirectory(t, fakeLDAPS)
	seedDirectory(d)
	p := newTestProvider(t, d, nil)
	last := func(user string) *pluginv1.AuthTestStep {
		resp, err := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: testConfig(t, d, configOverrides{configKeyUsers: {"test_username": user}})})
		if err != nil {
			t.Fatal(err)
		}
		steps := resp.GetSteps()
		return steps[len(steps)-1]
	}
	if step := last("nobody"); step.GetId() != "test_user" || step.GetOk() || !strings.Contains(step.GetMessage(), "nobody") {
		t.Fatalf("unknown test user: %v", step)
	}
	if step := last("alice"); !step.GetOk() || !strings.Contains(step.GetMessage(), "role user") {
		t.Fatalf("plain user: %v", step)
	}
}
