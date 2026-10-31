package okta

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID = "0oatestclient"
	testKeyID    = "test-kid"
)

// fakeOkta checks client assertions and DPoP proofs the way Okta does and serves a two-page System Log.
type fakeOkta struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu            sync.Mutex
	tokenCalls    int
	logCalls      int
	issued        []string
	tokenNonce    string
	resourceNonce string
	challenged    bool
	revokeNext    bool
}

func newFakeOkta(t *testing.T) *fakeOkta {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOkta{t: t, key: key, tokenNonce: "nonce-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+tokenPath, f.token)
	mux.HandleFunc("GET "+logsPath, f.logs)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOkta) client(t *testing.T) *client {
	t.Helper()
	org, err := parseOrgURL(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := newDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	return newClient(org, testClientID, testKeyID, f.key, dk, f.srv.Client().Transport, 1000)
}

func (f *fakeOkta) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenCalls++
	tokenURL := f.srv.URL + tokenPath
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("token form: %v", err)
	}
	if got := r.PostForm.Get("scope"); got != logsScope {
		f.t.Errorf("scope = %q", got)
	}
	if got := r.PostForm.Get("client_assertion_type"); got != assertionType {
		f.t.Errorf("client_assertion_type = %q", got)
	}
	assertion, err := jwt.Parse(r.PostForm.Get("client_assertion"),
		func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(testClientID), jwt.WithSubject(testClientID),
		jwt.WithAudience(tokenURL), jwt.WithExpirationRequired())
	if err != nil || assertion.Header["kid"] != testKeyID {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"The client_assertion signature is invalid."}`)
		return
	}
	claims := verifyProof(f.t, r.Header.Get("DPoP"), http.MethodPost, tokenURL)
	if claims["nonce"] != f.tokenNonce {
		w.Header().Set("DPoP-Nonce", f.tokenNonce)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof."}`)
		return
	}
	tok := fmt.Sprintf("token-%d", len(f.issued)+1)
	f.issued = append(f.issued, tok)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token_type":"DPoP","expires_in":3600,"access_token":%q,"scope":"okta.logs.read"}`, tok)
}

func (f *fakeOkta) logs(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logCalls++
	scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	current := len(f.issued) > 0 && tok == f.issued[len(f.issued)-1]
	if scheme != "DPoP" || !current || f.revokeNext {
		f.revokeNext = false
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims := verifyProof(f.t, r.Header.Get("DPoP"), http.MethodGet, f.srv.URL+logsPath)
	sum := sha256.Sum256([]byte(tok))
	if claims["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		f.t.Errorf("ath does not match the access token")
	}
	if f.resourceNonce != "" && claims["nonce"] != f.resourceNonce {
		f.challenged = true
		w.Header().Set("DPoP-Nonce", f.resourceNonce)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	self := f.srv.URL + logsPath + "?" + r.URL.RawQuery
	next := f.srv.URL + logsPath + "?sortOrder=ASCENDING&after=2"
	w.Header().Add("Link", "<"+self+`>; rel="self"`)
	w.Header().Add("Link", "<"+next+`>; rel="next"`)
	w.Header().Set("X-Rate-Limit-Limit", "60")
	w.Header().Set("X-Rate-Limit-Remaining", "59")
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("after") != "" {
		fmt.Fprint(w, `[]`)
		return
	}
	fmt.Fprint(w, `[{"uuid":"u-1","published":"2026-10-29T11:27:10.350Z","eventType":"user.session.start"},
		{"uuid":"u-2","published":"2026-10-29T11:28:00.000Z","eventType":"user.lifecycle.suspend"}]`)
}

// verifyProof checks a DPoP proof's header, signature against its embedded key, method and URL.
func verifyProof(t *testing.T, proof, method, wantURL string) jwt.MapClaims {
	t.Helper()
	tok, err := jwt.Parse(proof, func(tok *jwt.Token) (any, error) {
		jwk, _ := tok.Header["jwk"].(map[string]any)
		x, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["x"]))
		y, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["y"]))
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Errorf("dpop proof: %v", err)
		return jwt.MapClaims{}
	}
	if tok.Header["typ"] != "dpop+jwt" {
		t.Errorf("dpop typ = %v", tok.Header["typ"])
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["htm"] != method || claims["htu"] != wantURL || claims["jti"] == "" {
		t.Errorf("dpop claims = %v, want htm %s htu %s", claims, method, wantURL)
	}
	return claims
}

func TestClientHandlesNonceAndCachesToken(t *testing.T) {
	f := newFakeOkta(t)
	c := f.client(t)
	ctx := context.Background()

	p, err := c.page(ctx, c.start(time.Now().Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.events) != 2 || !c.owns(p.next) || p.limit != 60 || p.remaining != 59 {
		t.Fatalf("page = %d events, next %q, limit %d/%d", len(p.events), p.next, p.remaining, p.limit)
	}
	if _, err := c.page(ctx, p.next); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 2 || len(f.issued) != 1 {
		t.Fatalf("token calls = %d, issued = %d; want one nonce challenge then one token reused for both pages", f.tokenCalls, len(f.issued))
	}
}

func TestClientAnswersResourceNonceChallenge(t *testing.T) {
	f := newFakeOkta(t)
	f.resourceNonce = "resource-nonce"
	c := f.client(t)
	if _, err := c.page(context.Background(), c.start(time.Now())); err != nil {
		t.Fatal(err)
	}
	if !f.challenged || f.logCalls != 2 {
		t.Fatalf("challenged = %v, log calls = %d; want one challenge and one retry", f.challenged, f.logCalls)
	}
}

func TestClientRefreshesRejectedToken(t *testing.T) {
	f := newFakeOkta(t)
	c := f.client(t)
	ctx := context.Background()
	if _, err := c.page(ctx, c.start(time.Now())); err != nil {
		t.Fatal(err)
	}
	f.revokeNext = true
	if _, err := c.page(ctx, c.start(time.Now())); err != nil {
		t.Fatal(err)
	}
	if len(f.issued) != 2 {
		t.Fatalf("issued = %d tokens; want a new token after invalid_token", len(f.issued))
	}
}

func TestTokenEndpointRejectionIsUnavailable(t *testing.T) {
	f := newFakeOkta(t)
	org, _ := parseOrgURL(f.srv.URL)
	dk, _ := newDPoPKey()
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := newClient(org, testClientID, testKeyID, other, dk, f.srv.Client().Transport, 1000)
	_, err := c.page(context.Background(), c.start(time.Now()))
	if err == nil || !unavailable(err) || retryable(err) {
		t.Fatalf("err = %v; want an unavailable, non-retryable auth error", err)
	}
}

func TestLoadRSAKeyFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	cases := []struct {
		name  string
		block *pem.Block
		ok    bool
	}{
		{"pkcs8", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}, true},
		{"pkcs1", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, true},
		{"ec", &pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}, false},
		{"cert", &pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}, false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), c.name+".pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(c.block), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadRSAKey(path)
		if c.ok && (err != nil || !got.Equal(key)) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: want an error", c.name)
		}
	}
}

func TestHTUDropsQuery(t *testing.T) {
	u, _ := url.Parse("https://example.okta.com/api/v1/logs?since=x&after=1#frag")
	if got := htu(u); got != "https://example.okta.com/api/v1/logs" {
		t.Fatalf("htu = %q", got)
	}
}

func TestProofCarriesAccessTokenHash(t *testing.T) {
	dk, err := newDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dk.proof(http.MethodGet, "https://example.okta.com/api/v1/logs", "n", "tok", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyProof(t, proof, http.MethodGet, "https://example.okta.com/api/v1/logs")
	sum := sha256.Sum256([]byte("tok"))
	if claims["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) || claims["nonce"] != "n" {
		raw, _ := json.Marshal(claims)
		t.Fatalf("claims = %s", raw)
	}
}
