package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/golang/glog"

	"codemk8/goants/pkg/auth"
	"codemk8/goants/pkg/token"
)

const (
	dbname = "user_token.db"
)

var (
	port = flag.Int("port", 3000, "The webhook server port")
	// TLS files
	tlsCertFile = flag.String("tlsCertFile", "./ca.pem", "The TLS certificate file")
	tlsPriKey   = flag.String("tlsPriKey", "./ca-key.pem", "The TLS private key file")

	loginAttri = "uid"
)

// ServiceHandler serves the authentication/authorization webhooks for k8s cluster
type ServiceHandler struct {
	TokenSigner   token.Signer
	TokenVerifier token.Verifier
	User          auth.User
}

// TokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
func (p ServiceHandler) login(req *restful.Request, resp *restful.Response) {
	user, password, ok := req.Request.BasicAuth()

	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		glog.V(2).Infof("user %s failed to authorize", user)
		return
	}

	// Authenticate the user via LDAP
	ldapEntry, err := p.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		glog.V(2).Infof("Error authenticating user %s: %v", user, err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// If gets here, user is authenticated, generate a token for this user
	token := p.createToken(user, ldapEntry)

	// Sign token and return
	signedToken, err := p.TokenSigner.Sign(token)
	if err != nil {
		glog.V(2).Infof("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = p.User.Login(&user, &signedToken)
	if err != nil {
		glog.V(2).Infof("Error adding token to db: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	glog.V(2).Infof("Successfully generated token for user %s", user)
	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func extractTokenFromHeader(authHeader string) *string {
	// Remove the "Bearer " prefix
	bearerAndToken := strings.Split(authHeader, " ")
	if len(bearerAndToken) == 2 {
		return &bearerAndToken[1]
	}
	glog.V(2).Infof("HEADER is invalid: %v", bearerAndToken)
	return nil
}

// auth from web frontend
func (p LDAPServiceHandler) auth(req *restful.Request, resp *restful.Response) {
	bToken := extractTokenFromHeader(req.Request.Header.Get("Authorization"))
	if bToken == nil {
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Verify token
	claim, err := p.TokenVerifier.Verify(*bToken)
	if err != nil {
		glog.V(2).Infof("Token is invalid: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	authed := p.User.Authenticate(&claim.Username, bToken)
	if !authed {
		glog.V(2).Infof("Error authenticating token in db.")
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	status := token.AuthTokenStatus{
		Authenticated: true,
		Username:      claim.Username,
		Isa:           claim.Isa,
		Assertions:    claim.Assertions,
	}

	respJSON, err := json.Marshal(status)
	if err != nil {
		glog.V(2).Infof("Error marshalling response: %v during authentication", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	glog.V(2).Infof("User %s authenticated", claim.Username)
	resp.Header().Add("Content-Type", "application/json")
	resp.Write(respJSON)
}

func (p LDAPServiceHandler) logout(req *restful.Request, resp *restful.Response) {
	bToken := extractTokenFromHeader(req.Request.Header.Get("Authorization"))
	if bToken == nil {
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Verify token
	claim, err := p.TokenVerifier.Verify(*bToken)
	if err != nil {
		glog.V(0).Infof("Token is invalid: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}
	err = p.User.Logout(&claim.Username, bToken)
	if err != nil {
		glog.V(0).Infof("Failed to logout user %s", claim.Username)
	} else {
		glog.V(2).Infof("Successfully revoked a token from user %s", claim.Username)
	}
}

func (p LDAPServiceHandler) createToken(username string, ldapEntry *goldap.Entry) *token.AuthToken {
	return &token.AuthToken{
		Username: username,
		Isa:      time.Now().Format("2016-10-02 11:11:11"),
		Assertions: map[string]string{
			"userDN": ldapEntry.DN,
		},
	}
}

// Register routes
func (p LDAPServiceHandler) register() {
	ws := new(restful.WebService)
	ws.Route(ws.GET("/login").To(p.login))
	ws.Route(ws.POST("/auth").To(p.auth))
	ws.Route(ws.POST("/logout").To(p.logout))

	// k8s webhooks
	ws.Route(ws.POST("/authenticate").To(p.authenticate))
	//ws.Route(ws.POST("/authorize").To(p.authorize))
	restful.Add(ws)
}

func main() {
	flag.Parse()

	ldapClient := ldap.Client{
		BaseDN:             *baseDN,
		LdapServer:         *ldapServer,
		LdapPort:           *ldapPort,
		AllowInsecure:      true,
		UserLoginAttribute: loginAttri,
		SearchUserDN:       *bindUserDN,
		SearchUserPassword: *bindUserPasswd,
		TLSConfig:          nil,
	}

	keypairFilename := "/etc/secret-volume/signing"
	if err := token.CheckKeyPair(keypairFilename); err != nil {
		glog.Fatalf("Error generating key pair: %v", err)
	}

	tokenSigner, err := token.NewJSigner(keypairFilename)
	if err != nil {
		glog.Fatalf("Error creating token issuer: %v", err)
	}

	tokenVerifier, err := token.NewVerifier(keypairFilename)
	if err != nil {
		glog.Fatalf("Error creating token verifier: %v", err)
	}

	user, err := auth.NewLvldbUser(dbname)
	ldapService := LDAPServiceHandler{LDAPAuthenticator: ldapClient,
		TokenSigner:   tokenSigner,
		TokenVerifier: tokenVerifier,
		User:          user}

	ldapService.register()
	glog.V(0).Infof("Running https server on %d", *port)
	glog.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *port), *tlsCertFile, *tlsPriKey, nil))
}
