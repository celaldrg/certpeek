package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tlsServer(t *testing.T) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // we hang up right after the handshake
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool, strings.TrimPrefix(srv.URL, "https://")
}

func opts(roots *x509.CertPool) Options {
	return Options{WarnDays: 21, CritDays: 7, Timeout: 3 * time.Second, Roots: roots}
}

func TestParseTarget(t *testing.T) {
	cases := map[string][2]string{
		"example.com":              {"example.com", "443"},
		"example.com:8443":         {"example.com", "8443"},
		"https://example.com/a?b":  {"example.com", "443"},
		"https://example.com:9443": {"example.com", "9443"},
		"[::1]:8443":               {"::1", "8443"},
		"  spaced.example.org ":    {"spaced.example.org", "443"},
	}
	for in, want := range cases {
		h, p, err := ParseTarget(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Errorf("ParseTarget(%q) = %q, %q, %v; want %q, %q", in, h, p, err, want[0], want[1])
		}
	}
	if _, _, err := ParseTarget(""); err == nil {
		t.Error("expected error for empty target")
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		days int
		want Status
	}{{100, StatusOK}, {22, StatusOK}, {21, StatusWarn}, {8, StatusWarn}, {7, StatusCritical}, {0, StatusCritical}, {-3, StatusCritical}} {
		if got := Classify(c.days, 21, 7); got != c.want {
			t.Errorf("Classify(%d) = %v, want %v", c.days, got, c.want)
		}
	}
}

func TestTrustedCertificateIsOK(t *testing.T) {
	srv, pool, addr := tlsServer(t)
	r := Check(context.Background(), strings.Replace(addr, "127.0.0.1", "127.0.0.1", 1), opts(pool))
	if r.Status != StatusOK || r.Error != "" || len(r.Problems) != 0 {
		t.Fatalf("got %+v", r)
	}
	if want := srv.Certificate().NotAfter.UTC(); !r.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", r.NotAfter, want)
	}
	if r.TLSVersion != "TLS1.3" {
		t.Errorf("TLSVersion = %q", r.TLSVersion)
	}
}

func TestExpiryWindows(t *testing.T) {
	srv, pool, addr := tlsServer(t)
	exp := srv.Certificate().NotAfter
	for _, c := range []struct {
		before time.Duration
		want   Status
		days   int
	}{
		{30 * 24 * time.Hour, StatusOK, 30},
		{10*24*time.Hour + time.Hour, StatusWarn, 10},
		{3*24*time.Hour + time.Hour, StatusCritical, 3},
	} {
		o := opts(pool)
		now := exp.Add(-c.before)
		o.Now = func() time.Time { return now }
		r := Check(context.Background(), addr, o)
		if r.Status != c.want || r.DaysLeft != c.days {
			t.Errorf("%v before expiry: status %v days %d; want %v %d (%v)", c.before, r.Status, r.DaysLeft, c.want, c.days, r.Problems)
		}
	}
}

func TestExpired(t *testing.T) {
	srv, pool, addr := tlsServer(t)
	o := opts(pool)
	now := srv.Certificate().NotAfter.Add(48 * time.Hour)
	o.Now = func() time.Time { return now }
	r := Check(context.Background(), addr, o)
	if r.Status != StatusCritical || r.DaysLeft >= 0 || !contains(r.Problems, "expired") {
		t.Fatalf("got %+v", r)
	}
}

func TestUntrustedAndHostnameMismatch(t *testing.T) {
	_, pool, addr := tlsServer(t)
	r := Check(context.Background(), addr, opts(nil)) // system roots do not trust httptest's CA
	if r.Status != StatusCritical || len(r.Problems) == 0 {
		t.Fatalf("untrusted: got %+v", r)
	}
	port := addr[strings.LastIndex(addr, ":")+1:]
	r = Check(context.Background(), "localhost:"+port, opts(pool))
	if !contains(r.Problems, "hostname mismatch") {
		t.Fatalf("mismatch: got %+v", r)
	}
}

func TestConnectionError(t *testing.T) {
	r := Check(context.Background(), "127.0.0.1:1", opts(nil))
	if r.Status != StatusError || r.Error == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestCLIJSONAndExitCode(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-json", "-timeout", "2s", "127.0.0.1:1"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	var rs []Result
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil || len(rs) != 1 || rs[0].Status != StatusError {
		t.Fatalf("json: %v %s", err, out.String())
	}
	if !strings.Contains(out.String(), `"status": "ERROR"`) {
		t.Errorf("status not rendered as text: %s", out.String())
	}
	if run(nil, &out, &errb) != 3 {
		t.Error("no targets should exit 3")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
