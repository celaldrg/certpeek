// Package main implements certpeek, a TLS certificate expiry checker.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Status of a checked endpoint, ordered by severity.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusCritical
	StatusError
)

func (s Status) String() string {
	return [...]string{"OK", "WARN", "CRITICAL", "ERROR"}[s]
}

// MarshalText makes Status render as a word in JSON.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a status word.
func (s *Status) UnmarshalText(b []byte) error {
	for i, n := range [...]string{"OK", "WARN", "CRITICAL", "ERROR"} {
		if string(b) == n {
			*s = Status(i)
			return nil
		}
	}
	return fmt.Errorf("unknown status %q", b)
}

// Result is what certpeek reports for one endpoint.
type Result struct {
	Target     string    `json:"target"`
	Address    string    `json:"address"`
	Status     Status    `json:"status"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	DaysLeft   int       `json:"days_left"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Problems   []string  `json:"problems,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Options controls a check.
type Options struct {
	WarnDays int
	CritDays int
	Timeout  time.Duration
	Now      func() time.Time
	Roots    *x509.CertPool // nil = system roots
}

// ParseTarget turns "example.com", "example.com:8443" or "https://example.com/x" into host, port.
func ParseTarget(t string) (host, port string, err error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", "", errors.New("empty target")
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", "", fmt.Errorf("bad URL %q: %w", t, err)
		}
		host, port = u.Hostname(), u.Port()
		if port == "" {
			port = "443"
		}
		return host, port, nil
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		return h, p, nil
	}
	return strings.Trim(t, "[]"), "443", nil
}

var tlsNames = map[uint16]string{
	tls.VersionTLS10: "TLS1.0", tls.VersionTLS11: "TLS1.1", tls.VersionTLS12: "TLS1.2", tls.VersionTLS13: "TLS1.3",
}

// Check connects to target, reads the leaf certificate and classifies it.
func Check(ctx context.Context, target string, o Options) Result {
	r := Result{Target: target, Status: StatusError}
	host, port, err := ParseTarget(target)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Address = net.JoinHostPort(host, port)
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: o.Timeout},
		// We verify ourselves below so that we can still report on broken certificates.
		Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
	}
	cctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := dialer.DialContext(cctx, "tcp", r.Address)
	if err != nil {
		r.Error = cleanErr(err)
		return r
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		r.Error = "server sent no certificate"
		return r
	}
	leaf := state.PeerCertificates[0]
	r.Subject = leaf.Subject.CommonName
	r.Issuer = issuerName(leaf)
	r.DNSNames = leaf.DNSNames
	r.NotBefore, r.NotAfter = leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	r.TLSVersion = tlsNames[state.Version]
	t := now()
	r.DaysLeft = int(leaf.NotAfter.Sub(t).Hours() / 24)
	if leaf.NotAfter.Sub(t) < 0 {
		r.DaysLeft = -int(t.Sub(leaf.NotAfter).Hours()/24) - 1
	}

	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: o.Roots, CurrentTime: t})
	r.Status = Classify(r.DaysLeft, o.WarnDays, o.CritDays)
	if t.Before(leaf.NotBefore) {
		r.Problems = append(r.Problems, "not valid yet")
		r.Status = StatusCritical
	}
	if r.DaysLeft < 0 {
		r.Problems = append(r.Problems, "expired")
	}
	if verr != nil {
		var hn x509.HostnameError
		var ua x509.UnknownAuthorityError
		var inv x509.CertificateInvalidError
		switch {
		case errors.As(verr, &hn):
			r.Problems = append(r.Problems, "hostname mismatch")
		case errors.As(verr, &ua):
			if leaf.Issuer.String() == leaf.Subject.String() {
				r.Problems = append(r.Problems, "self-signed")
			} else {
				r.Problems = append(r.Problems, "untrusted issuer")
			}
		case errors.As(verr, &inv) && inv.Reason == x509.Expired:
			// already reported
		default:
			r.Problems = append(r.Problems, verr.Error())
		}
		if r.Status < StatusCritical {
			r.Status = StatusCritical
		}
	}
	if state.Version < tls.VersionTLS12 {
		r.Problems = append(r.Problems, "legacy "+r.TLSVersion)
		if r.Status < StatusWarn {
			r.Status = StatusWarn
		}
	}
	return r
}

// Classify maps days left to a status.
func Classify(daysLeft, warn, crit int) Status {
	switch {
	case daysLeft <= crit:
		return StatusCritical
	case daysLeft <= warn:
		return StatusWarn
	default:
		return StatusOK
	}
}

func issuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		if c.Issuer.CommonName != "" && c.Issuer.CommonName != c.Issuer.Organization[0] {
			return c.Issuer.Organization[0] + " (" + c.Issuer.CommonName + ")"
		}
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

func cleanErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed: " + dnsErr.Err
	}
	if errors.Is(err, io.EOF) {
		return "connection closed during TLS handshake (EOF)"
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout") {
		return "timed out"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.HasPrefix(s, "dial tcp") {
		return s[i+2:]
	}
	return s
}
