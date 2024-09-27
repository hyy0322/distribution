package handlers

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/gorilla/handlers"
)

type remoteAuthChallenger struct {
	remoteURL url.URL
	sync.Mutex
	cm challenge.Manager
	cs auth.CredentialStore
}

var authChallenger *remoteAuthChallenger
var once sync.Once

func tokenDispatcher(ctx *Context, r *http.Request) http.Handler {

	tokenHandler := &tokenHandler{
		Context: ctx,
	}

	return handlers.MethodHandler{
		"GET": http.HandlerFunc(tokenHandler.GetToken),
	}
}

type tokenHandler struct {
	*Context
}

const (
	issuer   = "cr-cache"
	audience = "cr-cache"
)

// Token represents the json returned by registry token service
type Token struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

const challengeHeader = "Docker-Distribution-Api-Version"

// tryEstablishChallenges will attempt to get a challenge type for the upstream if none currently exist
func (r *remoteAuthChallenger) tryEstablishChallenges(ctx *Context) error {
	r.Lock()
	defer r.Unlock()

	remoteURL := r.remoteURL
	remoteURL.Path = "/v2/"
	challenges, err := r.cm.GetChallenges(remoteURL)
	if err != nil {
		return err
	}

	if len(challenges) > 0 {
		return nil
	}

	// establish challenge type with upstream
	if err := ping(r.cm, remoteURL.String(), challengeHeader); err != nil {
		return err
	}

	context.GetLogger(ctx).Infof("Challenge established with upstream : %s %s", remoteURL, r.cm)
	return nil
}

func (r *remoteAuthChallenger) getChallenges() ([]challenge.Challenge, error) {
	r.Lock()
	defer r.Unlock()
	remoteURL := r.remoteURL
	remoteURL.Path = "/v2/"

	return r.cm.GetChallenges(remoteURL)
}

func ping(manager challenge.Manager, endpoint, versionHeader string) error {
	resp, err := http.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return manager.AddResponse(resp)
}

func (h *tokenHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	var (
		user, pwd string
	)
	if len(r.Header["Authorization"]) == 0 {
		context.GetLogger(h).Info("anonymous access")
	} else {
		user, pwd, _ = r.BasicAuth()
	}

	var err error
	defer func() {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			h.Errors = append(h.Errors, errcode.ErrorCodeUnauthorized.WithDetail(err))
			return
		}
		w.WriteHeader(http.StatusOK)
	}()

	once.Do(func() {
		var remoteURL *url.URL
		remoteURL, err = url.Parse(h.App.Config.Proxy.RemoteURL)
		if err != nil {
			panic(err)
		}
		authChallenger = &remoteAuthChallenger{
			remoteURL: *remoteURL,
			cm:        challenge.NewSimpleManager(),
		}
	})
	err = authChallenger.tryEstablishChallenges(h.Context)
	if err != nil {
		context.GetLogger(h).Error("establish challenges error", err)
		return
	}

	challenges, err := authChallenger.getChallenges()
	if err != nil {
		context.GetLogger(h).Error("establish challenges error", err)
		return
	}

	context.GetLogger(h).Info("challenge is ", challenges)
	var bearerChallenge *challenge.Challenge
	for _, c := range challenges {
		if c.Scheme == "bearer" {
			bearerChallenge = &c
		}
	}
	if bearerChallenge == nil {
		err = fmt.Errorf("no bearer challenge")
		context.GetLogger(h).Error("no bearer challenge")
		return
	}

	realm, ok := bearerChallenge.Parameters["realm"]
	if !ok {
		err = fmt.Errorf("no realm specified for token auth challenge")
		context.GetLogger(h).Error("no realm specified for token auth challenge", err)
		return
	}

	req, err := http.NewRequest(http.MethodGet, realm, nil)
	if err != nil {
		context.GetLogger(h).Error("new request for RemoteAuthURL error", err)
		return
	}

	if user == "" && pwd == "" {
		user, pwd = h.App.Config.Proxy.Username, h.App.Config.Proxy.Password
	}

	if user != "" && pwd != "" {
		req.SetBasicAuth(user, pwd)
	}
	q := req.URL.Query()
	scope := r.URL.Query()["scope"]

	q["scope"] = scope
	q["service"] = []string{bearerChallenge.Parameters["service"]}
	req.URL.RawQuery = q.Encode()

	context.GetLogger(h).Info("start to get token with user ", user)

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		context.GetLogger(h).Error("request remote auth token error ", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("remote auth token return unexpected code: %d", resp.StatusCode)
		context.GetLogger(h).Error("remote auth token return unexpected code ", resp.StatusCode)
		return
	}

	decoder := json.NewDecoder(resp.Body)

	var t Token
	if err = decoder.Decode(&t); err != nil {
		context.GetLogger(h).Error("unable to decode token response ", err)
		return
	}

	tokenSplit := strings.Split(t.Token, token.TokenSeparator)
	if len(tokenSplit) != 3 {
		context.GetLogger(h).Error("invalid token from proxy remote")
		err = fmt.Errorf("invalid token from proxy remote")
		return
	}

	var (
		rawClaims  = tokenSplit[1]
		claimsJSON []byte
		claim      = &token.ClaimSet{}
	)

	if claimsJSON, err = token.JoseBase64UrlDecode(rawClaims); err != nil {
		context.GetLogger(h).Error("unable to decode claims ", err)
		return
	}

	if err = json.Unmarshal(claimsJSON, claim); err != nil {
		context.GetLogger(h).Error("unmarshal claims error ", err)
		return
	}

	randomBytes := make([]byte, 15)
	if _, err = rand.Read(randomBytes); err != nil {
		context.GetLogger(h).Error("unable to read random bytes for jwt id ", err)
		return
	}

	joseHeader := &token.Header{
		Type:       "JWT",
		SigningAlg: "RS256",
		KeyID:      h.signKey.KeyID(),
	}

	claimSet := &token.ClaimSet{
		Issuer:      issuer,
		Subject:     claim.Subject,
		Audience:    audience,
		Expiration:  claim.Expiration - 60,
		NotBefore:   claim.NotBefore,
		IssuedAt:    claim.IssuedAt,
		JWTID:       base64.URLEncoding.EncodeToString(randomBytes),
		Access:      claim.Access,
		OriginToken: t.Token,
	}

	var joseHeaderBytes, claimSetBytes []byte

	if joseHeaderBytes, err = json.Marshal(joseHeader); err != nil {
		context.GetLogger(h).Error("unable to marshal jose header ", err)
		return

	}
	if claimSetBytes, err = json.Marshal(claimSet); err != nil {
		context.GetLogger(h).Error("unable to marshal claim set ", err)
		return
	}

	encodedJoseHeader := token.JoseBase64UrlEncode(joseHeaderBytes)
	encodedClaimSet := token.JoseBase64UrlEncode(claimSetBytes)
	payload := fmt.Sprintf("%s.%s", encodedJoseHeader, encodedClaimSet)

	var signatureBytes []byte
	if signatureBytes, _, err = h.signKey.Sign(strings.NewReader(payload), crypto.SHA256); err != nil {
		context.GetLogger(h).Error("unable to sign jwt payload ", err)
		return
	}

	signature := token.JoseBase64UrlEncode(signatureBytes)
	tokenString := fmt.Sprintf("%s.%s", payload, signature)
	jwtToken, err := token.NewToken(tokenString)

	t.Token = jwtToken.CompactRaw()
	t.ExpiresIn = t.ExpiresIn - 60

	enc := json.NewEncoder(w)
	if err = enc.Encode(t); err != nil {
		context.GetLogger(h).Error("json encode token error ", err)
		return
	}
}
