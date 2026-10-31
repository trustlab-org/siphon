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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	logsScope        = "okta.logs.read"
	assertionType    = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionLife    = 5 * time.Minute
	maxRefreshMargin = 5 * time.Minute
	maxErrorBody     = 64 << 10
)

type authError struct {
	status      int
	code        string
	description string
}

func (e *authError) Error() string {
	return fmt.Sprintf("okta token endpoint: %d %s: %s", e.status, e.code, e.description)
}

type accessToken struct {
	value  string
	scheme string
}

type tokenSource struct {
	http     *http.Client
	tokenURL string
	clientID string
	keyID    string
	key      *rsa.PrivateKey
	dpop     *dpopKey
	now      func() time.Time

	mu        sync.Mutex
	token     accessToken
	refreshAt time.Time
	nonce     string
}

func (ts *tokenSource) get(ctx context.Context) (accessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.token.value != "" && ts.now().Before(ts.refreshAt) {
		return ts.token, nil
	}
	tok, err := ts.request(ctx)
	if err != nil {
		var aerr *authError
		if errors.As(err, &aerr) && aerr.code == "use_dpop_nonce" && ts.nonce != "" {
			tok, err = ts.request(ctx)
		}
		if err != nil {
			return accessToken{}, err
		}
	}
	return tok, nil
}

func (ts *tokenSource) invalidate() {
	ts.mu.Lock()
	ts.token = accessToken{}
	ts.mu.Unlock()
}

func (ts *tokenSource) request(ctx context.Context) (accessToken, error) {
	assertion, err := ts.assertion()
	if err != nil {
		return accessToken{}, err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {logsScope},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return accessToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	proof, err := ts.dpop.proof(http.MethodPost, ts.tokenURL, ts.nonce, "", ts.now())
	if err != nil {
		return accessToken{}, err
	}
	req.Header.Set("DPoP", proof)

	resp, err := ts.http.Do(req)
	if err != nil {
		return accessToken{}, err
	}
	defer resp.Body.Close()
	if n := resp.Header.Get("DPoP-Nonce"); n != "" {
		ts.nonce = n
	}
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&body)
		return accessToken{}, &authError{status: resp.StatusCode, code: body.Error, description: body.Description}
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&body); err != nil {
		return accessToken{}, fmt.Errorf("decode token response: %w", err)
	}
	if body.AccessToken == "" || body.ExpiresIn <= 0 {
		return accessToken{}, errors.New("token response without access_token or expires_in")
	}
	life := time.Duration(body.ExpiresIn) * time.Second
	ts.token = accessToken{value: body.AccessToken, scheme: body.TokenType}
	ts.refreshAt = ts.now().Add(life - min(maxRefreshMargin, life/2))
	return ts.token, nil
}

func (ts *tokenSource) assertion() (string, error) {
	now := ts.now()
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": ts.clientID,
		"sub": ts.clientID,
		"aud": ts.tokenURL,
		"iat": now.Unix(),
		"exp": now.Add(assertionLife).Unix(),
		"jti": rand.Text(),
	})
	t.Header["kid"] = ts.keyID
	s, err := t.SignedString(ts.key)
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return s, nil
}

type dpopKey struct {
	priv *ecdsa.PrivateKey
	jwk  map[string]string
}

func newDPoPKey() (*dpopKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return &dpopKey{priv: priv, jwk: map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(point[1:33]),
		"y":   b64(point[33:65]),
	}}, nil
}

// proof builds a DPoP proof JWT (RFC 9449). accessToken is set for resource requests and empty for token requests
func (k *dpopKey) proof(method, htu, nonce, accessToken string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
		"jti": rand.Text(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64(sum[:])
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = "dpop+jwt"
	t.Header["jwk"] = k.jwk
	s, err := t.SignedString(k.priv)
	if err != nil {
		return "", fmt.Errorf("sign dpop proof: %w", err)
	}
	return s, nil
}

// dpopTransport authorizes each request with a fresh proof and retries once when Okta asks for a nonce or rejects a token.
type dpopTransport struct {
	base http.RoundTripper
	ts   *tokenSource

	mu    sync.Mutex
	nonce string
}

func (t *dpopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		tok, err := t.ts.get(req.Context())
		if err != nil {
			return nil, err
		}
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", tok.scheme+" "+tok.value)
		if strings.EqualFold(tok.scheme, "DPoP") {
			proof, err := t.ts.dpop.proof(req.Method, htu(req.URL), t.getNonce(), tok.value, t.ts.now())
			if err != nil {
				return nil, err
			}
			r.Header.Set("DPoP", proof)
		}
		resp, err := t.base.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if n := resp.Header.Get("DPoP-Nonce"); n != "" {
			t.setNonce(n)
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		switch {
		case strings.Contains(challenge, "use_dpop_nonce") && resp.Header.Get("DPoP-Nonce") != "":
		case strings.Contains(challenge, "invalid_token"):
			t.ts.invalidate()
		default:
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
	}
}

func (t *dpopTransport) getNonce() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonce
}

func (t *dpopTransport) setNonce(n string) {
	t.mu.Lock()
	t.nonce = n
	t.mu.Unlock()
}

// htu is the request URL without query or fragment, as RFC 9449 requires.
func htu(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

func loadRSAKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: key is %T, want RSA", path, k)
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("%s: unsupported PEM block %q", path, block.Type)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
